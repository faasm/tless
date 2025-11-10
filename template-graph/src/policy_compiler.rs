use crate::TemplateGraph;
use abe4::policy::Policy;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// # Description
///
/// Computes the deterministic identifier for a workflow.
///
/// # Arguments
///
/// * `workflow_name`: The name of the workflow.
///
/// # Returns
///
/// A BLAKE3 hash as a hex string.
pub fn get_workflow_id(workflow_name: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"wf:");
    hasher.update(workflow_name.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// # Description
///
/// Computes the deterministic identifier for a node.
///
/// # Arguments
///
/// * `workflow_name`: The name of the workflow.
/// * `node_name`: The name of the node.
///
/// # Returns
///
/// A BLAKE3 hash as a hex string.
pub fn get_node_id(workflow_name: &str, node_name: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"node:");
    hasher.update(workflow_name.as_bytes());
    hasher.update(b"|");
    hasher.update(node_name.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// # Description
///
/// Compiles the access control policies for each node in the workflow template
/// graph.
///
/// # Arguments
///
/// * `template_graph`: The workflow template graph.
///
/// # Returns
///
/// A `HashMap` where the keys are node names and the values are the compiled
/// `Policy` objects.
pub fn compile_policies(template_graph: &TemplateGraph) -> Result<HashMap<String, Policy>> {
    let mut policies = HashMap::new();
    let graph = build_graph(template_graph);

    let wf_id = get_workflow_id(&template_graph.workflow.name);

    for node in &template_graph.nodes {
        let n_id = get_node_id(&template_graph.workflow.name, &node.name);
        let ancestors = get_ancestors(&graph, &node.name);

        let mut policy_parts = Vec::new();

        // as_conjunction
        let as_conjunction: Vec<String> = template_graph
            .authorities
            .attestation_services
            .iter()
            .map(|as_service| {
                format!(
                    "({}.wf:{} & {}.node:{})",
                    as_service.id, wf_id, as_service.id, n_id
                )
            })
            .collect();
        policy_parts.push(as_conjunction.join(" & "));

        // anc_disjunction
        if !ancestors.is_empty() {
            let mut anc_disjunction: Vec<String> = ancestors
                .iter()
                .map(|ancestor| {
                    let ancestor_id = get_node_id(&template_graph.workflow.name, ancestor);
                    format!("{}.anc:{}", template_graph.authorities.user.id, ancestor_id)
                })
                .collect();
            anc_disjunction.sort();
            policy_parts.push(format!("({})", anc_disjunction.join(" | ")));
        }

        // node-specific policy
        if let Some(node_policy) = &node.node_policy {
            policy_parts.push(format!("{:?}", node_policy));
        }

        let policy_string = policy_parts.join(" & ");
        let policy = Policy::parse(&policy_string)?;
        policies.insert(node.name.clone(), policy);
    }

    Ok(policies)
}

pub fn build_graph(template_graph: &TemplateGraph) -> HashMap<String, Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = template_graph
        .nodes
        .iter()
        .map(|n| (n.name.clone(), Vec::new()))
        .collect();

    for (from, to) in &template_graph.edges {
        if let Some(adj) = graph.get_mut(from) {
            adj.push(to.clone());
        }
    }
    graph
}

pub fn get_ancestors(graph: &HashMap<String, Vec<String>>, node_name: &str) -> HashSet<String> {
    let mut reversed_graph: HashMap<String, Vec<String>> = HashMap::new();
    for node in graph.keys() {
        reversed_graph.entry(node.clone()).or_default();
    }
    for (from, to_nodes) in graph {
        for to in to_nodes {
            reversed_graph
                .entry(to.clone())
                .or_default()
                .push(from.clone());
        }
    }

    let mut ancestors = HashSet::new();
    let mut stack = vec![node_name.to_string()];
    let mut visited = HashSet::from([node_name.to_string()]);

    while let Some(current_node) = stack.pop() {
        if let Some(predecessors) = reversed_graph.get(&current_node) {
            for predecessor in predecessors {
                if !visited.contains(predecessor) {
                    ancestors.insert(predecessor.clone());
                    visited.insert(predecessor.clone());
                    stack.push(predecessor.clone());
                }
            }
        }
    }
    ancestors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TemplateGraph;

    #[test]
    fn test_get_ancestors_with_self_cycle() {
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();
        graph.insert("A".to_string(), vec!["A".to_string()]);

        let ancestors = get_ancestors(&graph, "A");
        assert!(!ancestors.contains("A"));
        assert!(ancestors.is_empty());
    }

    #[test]
    fn test_get_workflow_id() {
        let wf_name = "my_workflow";
        let wf_id = get_workflow_id(wf_name);
        assert_eq!(
            wf_id,
            "0f2d62b153aea5ae3fa1a05b7a0834010f38cb3953102245bcdbc942eb7b86f2"
        );
    }

    #[test]
    fn test_get_node_id() {
        let wf_name = "my_workflow";
        let node_name = "my_node";
        let node_id = get_node_id(wf_name, node_name);
        assert_eq!(
            node_id,
            "fe3d11de2b8ae7a5009a7fd7a4f563b18199ef01d9341a77ce232cc086c99d11"
        );
    }

    #[test]
    fn test_compile_policies() {
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

- name: merge_results
  function: merge_results

edges:
- [fetch_public,  run_audit]
- [fetch_private, run_audit]
- [run_audit,     merge_results]

output:
  dir: ./out-ciphertexts
        "#;

        let template_graph = TemplateGraph::from_yaml(yaml_content).unwrap();
        let policies = compile_policies(&template_graph).unwrap();

        let wf_id = get_workflow_id("fraud-detector");

        // Policy for fetch_public
        let fetch_public_id = get_node_id("fraud-detector", "fetch_public");
        let expected_policy = format!(
            "({}.wf:{} & {}.node:{})",
            "maa", wf_id, "maa", fetch_public_id
        );
        assert_eq!(
            format!("{:?}", policies.get("fetch_public").unwrap()),
            expected_policy
        );

        // Policy for fetch_private
        let fetch_private_id = get_node_id("fraud-detector", "fetch_private");
        let expected_policy = format!(
            "(({}.wf:{} & {}.node:{}) & finra.role:data_fetch)",
            "maa", wf_id, "maa", fetch_private_id
        );
        assert_eq!(
            format!("{:?}", policies.get("fetch_private").unwrap()),
            expected_policy
        );

        // Policy for run_audit
        let run_audit_id = get_node_id("fraud-detector", "run_audit");
        let fetch_public_anc_id = get_node_id("fraud-detector", "fetch_public");
        let fetch_private_anc_id = get_node_id("fraud-detector", "fetch_private");
        let mut ancestors = vec![
            format!("{}.anc:{}", "user_42", fetch_public_anc_id),
            format!("{}.anc:{}", "user_42", fetch_private_anc_id),
        ];
        ancestors.sort();
        let anc_policy = format!("({} | {})", ancestors[0], ancestors[1]);
        let expected_policy = format!(
            "(({}.wf:{} & {}.node:{}) & {})",
            "maa", wf_id, "maa", run_audit_id, anc_policy
        );
        assert_eq!(
            format!("{:?}", policies.get("run_audit").unwrap()),
            expected_policy
        );

        // Policy for merge_results
        let merge_results_id = get_node_id("fraud-detector", "merge_results");
        let run_audit_anc_id = get_node_id("fraud-detector", "run_audit");
        let fetch_public_anc_id = get_node_id("fraud-detector", "fetch_public");
        let fetch_private_anc_id = get_node_id("fraud-detector", "fetch_private");
        let mut ancestors = vec![
            format!("{}.anc:{}", "user_42", run_audit_anc_id),
            format!("{}.anc:{}", "user_42", fetch_public_anc_id),
            format!("{}.anc:{}", "user_42", fetch_private_anc_id),
        ];
        ancestors.sort();
        let anc_policy = format!("(({} | {}) | {})", ancestors[0], ancestors[1], ancestors[2]);
        let expected_policy = format!(
            "(({}.wf:{} & {}.node:{}) & {})",
            "maa", wf_id, "maa", merge_results_id, anc_policy
        );
        assert_eq!(
            format!("{:?}", policies.get("merge_results").unwrap()),
            expected_policy
        );
    }
}
