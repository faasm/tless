//! This module contains the common structures shared by diferent requests that the attestation
//! service receives.

use serde::Deserialize;

/// # Description
///
/// This structure contains the data that callers must provide to run CP-ABE key generation in the
/// attestation service.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeData {
    /// Unique global user identififer.
    pub gid: String,
    /// Workflow identifier.
    pub workflow_id: String,
    /// Node identifier within the workflow.
    pub node_id: String,
}
