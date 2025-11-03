use accless_abe4::{
    UserAttribute, decrypt, encrypt, iota::Iota, keygen, setup, tau::Tau,
};
use std::collections::HashSet;
use template_graph::{TemplateGraph, policy_compiler};

#[test]
fn test_encrypt_decrypt_workflow() {
    let yaml_content = r#"
version: 1
workflow:
  name: fraud-detector
  uid: user_42

authorities:
  attestation-services:
    - id: maa
      mpk_abe: base64:mpk_abe_maa
  aps:
    - id: finra
      mpk_abe: base64:mpk_abe_finra

nodes:
- name: fetch_public
  function: fetch_public_data

- name: fetch_private
  function: fetch_private_data
  node-policy: 'finra.role:data_fetch'

- name: run_audit
  function: run_audit_rules
  node-policy: '(finra.role:data_process)'

- name: merge_results
  function: merge_results

edges:
- [fetch_public,  run_audit]
- [fetch_private, run_audit]
- [run_audit,     merge_results]

output:
  dir: ./tests/out-ciphertexts
    "#;

    let template_graph = TemplateGraph::from_yaml(yaml_content).unwrap();
    let policies = policy_compiler::compile_policies(&template_graph);

    let mut rng = ark_std::test_rng();

    // Setup ABE
    let mut auths: HashSet<String> = template_graph
        .authorities
        .attestation_services
        .iter()
        .map(|a| a.id.clone())
        .collect();
    if let Some(aps) = &template_graph.authorities.aps {
        for ap in aps {
            auths.insert(ap.id.clone());
        }
    }
    auths.insert(template_graph.workflow.uid.clone());
    let auths_str: Vec<&str> = auths.iter().map(|s| s.as_str()).collect();
    let (msk, mpk) = setup(&mut rng, &auths_str);

    // Test encryption and decryption for each node
    for node in &template_graph.nodes {
        if let Some(policy) = policies.get(&node.name) {
            let (k_enc, ct) = encrypt(&mut rng, &mpk, &policy, &Tau::new(&policy));

            // Simulate a user with the required attributes
            let mut user_attrs = Vec::new();
            let wf_id = policy_compiler::get_workflow_id(&template_graph.workflow.name);
            let n_id = policy_compiler::get_node_id(&template_graph.workflow.name, &node.name);

            // Add attestation service attributes
            for as_service in &template_graph.authorities.attestation_services {
                user_attrs.push(UserAttribute::new(&as_service.id, "wf", &wf_id));
                user_attrs.push(UserAttribute::new(&as_service.id, "node", &n_id));
            }

            // Add ancestor attributes
            let graph = policy_compiler::build_graph(&template_graph);
            let ancestors = policy_compiler::get_ancestors(&graph, &node.name);
            for ancestor in ancestors {
                let ancestor_id =
                    policy_compiler::get_node_id(&template_graph.workflow.name, &ancestor);
                user_attrs.push(UserAttribute::new(
                    &template_graph.workflow.uid,
                    "anc",
                    &ancestor_id,
                ));
            }

            // Add node-specific policy attributes
            if let Some(node_policy) = &node.node_policy {
                for i in 0..node_policy.len() {
                    let (attr, _) = node_policy.get(i);
                    user_attrs.push(attr);
                }
            }

            let iota = Iota::new(&user_attrs);
            let usk = keygen(
                &mut rng,
                &template_graph.workflow.uid,
                &msk,
                &user_attrs,
                &iota,
            );

            let k_dec = decrypt(
                &usk,
                &template_graph.workflow.uid,
                &iota,
                &Tau::new(&policy),
                &policy,
                &ct,
            );

            assert!(k_dec.is_some());
            assert_eq!(k_enc, k_dec.unwrap());
        }
    }
}
