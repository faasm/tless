//! # Workflow Template Graph
//!
//! This module provides the data structures and parsing logic for Accless
//! workflow template graphs. A workflow template graph is a YAML file that
//! defines the structure of a serverless workflow, its security policies, and
//! its data dependencies.

pub mod policy_compiler;

use accless_abe4::policy::Policy;
use serde::{Deserialize, de::Error};
use std::path::PathBuf;

/// # Description
///
/// Represents the entire workflow template graph. It is the root of the YAML
/// file.
#[derive(Debug, Deserialize)]
pub struct TemplateGraph {
    /// The version of the template graph format.
    pub version: u32,
    /// The workflow definition.
    pub workflow: Workflow,
    /// The authorities that provide attributes for the workflow.
    pub authorities: Authorities,
    /// The nodes (functions) in the workflow graph.
    pub nodes: Vec<Node>,
    /// The edges (dependencies) between nodes in the workflow graph.
    pub edges: Vec<(String, String)>,
    /// The output directory for the encrypted state bundles.
    pub output: Output,
}

/// # Description
///
/// Defines the workflow's metadata.
#[derive(Debug, Deserialize)]
pub struct Workflow {
    /// A human-readable name for the workflow.
    pub name: String,
}

/// # Description
///
/// Defines the attribute-providing authorities for the workflow.
#[derive(Debug, Deserialize)]
pub struct Authorities {
    /// The user authority.
    pub user: UserAuthority,
    /// A list of attestation services. At least one is mandatory.
    #[serde(rename = "attestation-services")]
    pub attestation_services: Vec<AttestationService>,
    /// An optional list of attribute providing services.
    pub aps: Option<Vec<Aps>>,
}

/// # Description
///
/// Represents the user authority.
#[derive(Debug, Deserialize, Clone)]
pub struct UserAuthority {
    /// A unique user-identifier owning the workflow. Cannot contain dashes.
    pub id: String,
    /// The master public key of the user for ABE.
    pub mpk_abe: String,
}

/// # Description
///
/// Represents an attestation service.
#[derive(Debug, Deserialize)]
pub struct AttestationService {
    /// A unique identifier for the attestation service.
    pub id: String,
    /// The master public key of the attestation service for ABE.
    pub mpk_abe: String,
}

/// # Description
///
/// Represents an attribute providing service.
#[derive(Debug, Deserialize, Clone)]
pub struct Aps {
    /// A unique identifier for the attribute providing service.
    pub id: String,
    /// The master public key of the attribute providing service for ABE.
    pub mpk_abe: String,
}

/// # Description
///
/// Represents a node in the workflow graph.
#[derive(Debug, Deserialize)]
pub struct Node {
    /// The name of the node. Must be unique within the workflow.
    pub name: String,
    /// The name of the function to be executed by this node.
    pub function: String,
    /// An optional list of paths to files that constitute the node's state.
    #[serde(rename = "state-bundle")]
    pub state_bundle: Option<Vec<PathBuf>>,
    /// An optional access control policy for the node.
    ///
    /// The policy is a string that will be parsed into a
    /// `accless_abe4::policy::Policy`. The policy language only allows
    /// alphanumeric characters and underscores for attribute values. Dashes
    /// are not allowed.
    #[serde(rename = "node-policy")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_policy")]
    pub node_policy: Option<Policy>,
}

/// # Description
///
/// A custom deserializer for the `node_policy` field.
///
/// It parses a string into a `accless_abe4::policy::Policy`. It also checks
/// for the presence of dashes in the policy string and returns an error if
/// they are found.
fn deserialize_policy<'de, D>(deserializer: D) -> Result<Option<Policy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => {
            if s.contains('-') {
                return Err(serde::de::Error::custom(
                    "Policy attributes cannot contain dashes '-'. Use underscores '_' instead.",
                ));
            }
            Policy::parse(&s)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
        None => Ok(None),
    }
}

/// # Description
///
/// Defines the output directory for the encrypted state bundles.
#[derive(Debug, Deserialize)]
pub struct Output {
    /// The path to the output directory.
    pub dir: PathBuf,
}

impl TemplateGraph {
    /// # Description
    ///
    /// Parses a YAML string into a `TemplateGraph`.
    ///
    /// # Arguments
    ///
    /// * `yaml`: A string containing the YAML representation of the template
    ///   graph.
    ///
    /// # Returns
    ///
    /// A `Result` containing the parsed `TemplateGraph` or a
    /// `serde_yaml::Error`.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let graph: TemplateGraph = serde_yaml::from_str(yaml)?;

        let mut aps_ids: std::collections::HashSet<String> = graph
            .authorities
            .aps
            .as_ref()
            .map(|aps_vec| aps_vec.iter().map(|aps| aps.id.clone()).collect())
            .unwrap_or_default();
        aps_ids.insert(graph.authorities.user.id.clone());

        for node in &graph.nodes {
            if let Some(policy) = &node.node_policy {
                for i in 0..policy.len() {
                    let (attr, _) = policy.get(i);
                    if !aps_ids.contains(attr.authority()) {
                        return Err(serde_yaml::Error::custom(format!(
                            "Authority '{}' in node policy for '{}' not found in attribute providing services.",
                            attr.authority(),
                            node.name
                        ).as_str()));
                    }
                }
            }
        }

        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_template_graph() {
        let yaml_content = r#"
version: 1
workflow:
  name: fraud-detector

authorities:
  user:
    id: user_42
    mpk_abe: base64:mpk_abe_user
  attestation-services:
    - id: maa
      mpk_abe: base64:mpk_abe_maa
  aps:
    - id: finra
      mpk_abe: base64:mpk_abe_finra

nodes:
- name: fetch_public
  function: fetch_public_data
  state-bundle:
      - ./state/public_rules.json

- name: fetch_private
  function: fetch_private_data
  state-bundle:
      - ./state/secret_spec.json
  node-policy: 'finra.role:data_fetch'

- name: run_audit
  function: run_audit_rules
  state-bundle:
    - ./state/run_audit.wasm
  node-policy: '(finra.role:data_process)'

- name: merge_results
  function: merge_results
  state-bundle: []
  node-policy: null

edges:
- [fetch_public,  run_audit]
- [fetch_private, run_audit]
- [run_audit,     merge_results]

output:
  dir: ./out-ciphertexts
        "#;

        let template_graph = TemplateGraph::from_yaml(yaml_content).unwrap();

        assert_eq!(template_graph.version, 1);
        assert_eq!(template_graph.workflow.name, "fraud-detector");
        assert_eq!(template_graph.authorities.user.id, "user_42");

        assert_eq!(template_graph.authorities.attestation_services.len(), 1);
        assert_eq!(template_graph.authorities.attestation_services[0].id, "maa");
        assert_eq!(
            template_graph.authorities.attestation_services[0].mpk_abe,
            "base64:mpk_abe_maa"
        );

        assert!(template_graph.authorities.aps.is_some());
        let aps = template_graph.authorities.aps.as_ref().unwrap();
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0].id, "finra");
        assert_eq!(aps[0].mpk_abe, "base64:mpk_abe_finra");

        assert_eq!(template_graph.nodes.len(), 4);

        // Node: fetch_public
        assert_eq!(template_graph.nodes[0].name, "fetch_public");
        assert_eq!(template_graph.nodes[0].function, "fetch_public_data");
        assert!(template_graph.nodes[0].state_bundle.is_some());
        assert_eq!(
            template_graph.nodes[0].state_bundle.as_ref().unwrap()[0],
            PathBuf::from("./state/public_rules.json")
        );
        assert!(template_graph.nodes[0].node_policy.is_none());

        // Node: fetch_private
        assert_eq!(template_graph.nodes[1].name, "fetch_private");
        assert_eq!(template_graph.nodes[1].function, "fetch_private_data");
        assert!(template_graph.nodes[1].state_bundle.is_some());
        assert_eq!(
            template_graph.nodes[1].state_bundle.as_ref().unwrap()[0],
            PathBuf::from("./state/secret_spec.json")
        );
        assert!(template_graph.nodes[1].node_policy.is_some());
        assert_eq!(
            format!(
                "{:?}",
                template_graph.nodes[1].node_policy.as_ref().unwrap()
            ),
            "finra.role:data_fetch"
        );

        // Node: run_audit
        assert_eq!(template_graph.nodes[2].name, "run_audit");
        assert_eq!(template_graph.nodes[2].function, "run_audit_rules");
        assert!(template_graph.nodes[2].state_bundle.is_some());
        assert_eq!(
            template_graph.nodes[2].state_bundle.as_ref().unwrap()[0],
            PathBuf::from("./state/run_audit.wasm")
        );
        assert!(template_graph.nodes[2].node_policy.is_some());
        assert_eq!(
            format!(
                "{:?}",
                template_graph.nodes[2].node_policy.as_ref().unwrap()
            ),
            "finra.role:data_process"
        );

        // Node: merge_results
        assert_eq!(template_graph.nodes[3].name, "merge_results");
        assert_eq!(template_graph.nodes[3].function, "merge_results");
        assert!(template_graph.nodes[3].state_bundle.is_some());
        assert!(
            template_graph.nodes[3]
                .state_bundle
                .as_ref()
                .unwrap()
                .is_empty()
        );
        assert!(template_graph.nodes[3].node_policy.is_none());

        assert_eq!(template_graph.edges.len(), 3);
        assert_eq!(
            template_graph.edges[0],
            ("fetch_public".to_string(), "run_audit".to_string())
        );
        assert_eq!(
            template_graph.edges[1],
            ("fetch_private".to_string(), "run_audit".to_string())
        );
        assert_eq!(
            template_graph.edges[2],
            ("run_audit".to_string(), "merge_results".to_string())
        );

        assert_eq!(
            template_graph.output.dir,
            PathBuf::from("./out-ciphertexts")
        );
    }

    #[test]
    fn test_parse_template_graph_with_invalid_policy() {
        let yaml_content = r#"
version: 1
workflow:
  name: fraud-detector

authorities:
  user:
    id: user_42
    mpk_abe: base64:mpk_abe_user
  attestation-services:
    - id: maa
      mpk_abe: base64:mpk_abe_maa

nodes:
- name: fetch_private
  function: fetch_private_data
  node-policy: 'finra.role:data-fetch'

edges: []

output:
  dir: ./out-ciphertexts
        "#;

        let result = TemplateGraph::from_yaml(yaml_content);
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(
            error.to_string().contains(
                "Policy attributes cannot contain dashes '-'. Use underscores '_' instead."
            )
        );
    }

    #[test]
    fn test_parse_template_graph_with_unknown_policy_authority() {
        let yaml_content = r#"
version: 1
workflow:
  name: fraud-detector

authorities:
  user:
    id: user_42
    mpk_abe: base64:mpk_abe_user
  attestation-services:
    - id: maa
      mpk_abe: base64:mpk_abe_maa

nodes:
- name: fetch_private
  function: fetch_private_data
  node-policy: 'finra.role:data_fetch'

edges: []

output:
  dir: ./out-ciphertexts
        "#;

        let result = TemplateGraph::from_yaml(yaml_content);
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error.to_string().contains("Authority 'finra' in node policy for 'fetch_private' not found in attribute providing services."));
    }
}
