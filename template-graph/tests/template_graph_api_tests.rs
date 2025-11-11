use abe4::{
    UserAttribute, decrypt, encrypt,
    iota::Iota,
    keygen,
    scheme::types::{MPK, PartialMPK},
    setup,
    tau::Tau,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::engine::{Engine as _, general_purpose};
use std::collections::HashSet;
use template_graph::{TemplateGraph, policy_compiler};

/// # Description
///
/// Helper method to construct a full MPK from a template graph.
fn get_full_mpk_from_template_graph(template_graph: &TemplateGraph) -> MPK {
    let mut mpk = MPK::new();

    // User authority
    let user_mpk_bytes = general_purpose::STANDARD
        .decode(&template_graph.authorities.user.mpk_abe)
        .unwrap();
    let user_partial_mpk = PartialMPK::deserialize_compressed(&user_mpk_bytes[..]).unwrap();
    mpk.add_partial_key(user_partial_mpk);

    // Attestation services
    for as_service in &template_graph.authorities.attestation_services {
        let as_mpk_bytes = general_purpose::STANDARD
            .decode(&as_service.mpk_abe)
            .unwrap();
        let as_partial_mpk = PartialMPK::deserialize_compressed(&as_mpk_bytes[..]).unwrap();
        mpk.add_partial_key(as_partial_mpk);
    }

    // APS
    if let Some(aps_vec) = &template_graph.authorities.attribute_providing_services {
        for aps in aps_vec {
            let aps_mpk_bytes = general_purpose::STANDARD.decode(&aps.mpk_abe).unwrap();
            let aps_partial_mpk = PartialMPK::deserialize_compressed(&aps_mpk_bytes[..]).unwrap();
            mpk.add_partial_key(aps_partial_mpk);
        }
    }

    mpk
}

#[test]
fn test_encrypt_decrypt_workflow_with_real_mpk() {
    let yaml_content = r#"
version: 1
workflow:
  name: fraud-detector

authorities:
  user:
    id: user_42
    mpk_abe: ""
  attestation-services:
    - id: maa
      mpk_abe: ""
  attribute-providing-services:
    - id: finra
      mpk_abe: ""

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

    let mut template_graph = TemplateGraph::from_yaml(yaml_content).unwrap();

    let mut rng = ark_std::test_rng();

    // Setup ABE and get partial MPKs
    let mut auths: HashSet<String> = template_graph
        .authorities
        .attestation_services
        .iter()
        .map(|a| a.id.clone())
        .collect();
    if let Some(aps) = &template_graph.authorities.attribute_providing_services {
        for ap in aps {
            auths.insert(ap.id.clone());
        }
    }
    auths.insert(template_graph.authorities.user.id.clone());
    let auths_str: Vec<&str> = auths.iter().map(|s| s.as_str()).collect();
    let (msk, mpk) = setup(&mut rng, &auths_str);

    // Update template graph with real MPKs
    for (auth, partial_mpk) in &mpk.partial_keys {
        let mut mpk_bytes = Vec::new();
        partial_mpk.serialize_compressed(&mut mpk_bytes).unwrap();
        let mpk_b64 = general_purpose::STANDARD.encode(&mpk_bytes);

        if auth == &template_graph.authorities.user.id {
            template_graph.authorities.user.mpk_abe = mpk_b64;
        } else if let Some(as_service) = template_graph
            .authorities
            .attestation_services
            .iter_mut()
            .find(|a| &a.id == auth)
        {
            as_service.mpk_abe = mpk_b64;
        } else if let Some(aps) = template_graph
            .authorities
            .attribute_providing_services
            .as_mut()
            .and_then(|aps_vec| aps_vec.iter_mut().find(|a| &a.id == auth))
        {
            aps.mpk_abe = mpk_b64;
        }
    }

    let policies = policy_compiler::compile_policies(&template_graph);
    let full_mpk = get_full_mpk_from_template_graph(&template_graph);

    // Test encryption and decryption for each node
    for node in &template_graph.nodes {
        if let Some(policy) = policies.as_ref().unwrap().get(&node.name) {
            let (k_enc, ct) = encrypt(&mut rng, &full_mpk, &policy, &Tau::new(&policy));

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
                    &template_graph.authorities.user.id,
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
                &template_graph.authorities.user.id,
                &msk,
                &user_attrs,
                &iota,
            );

            let k_dec = decrypt(
                &usk,
                &template_graph.authorities.user.id,
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
