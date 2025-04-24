use crate::attestation_service;
use crate::tasks::s3::S3;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key};
use rabe;
use serde::{Deserialize, Serialize};
use serde_yaml;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;

// Struct a node in our workflow DAG
#[derive(Debug, Serialize, Deserialize)]
struct DagFunc {
    name: String,
    scale: String,
    chains_to: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DagGraph {
    funcs: Vec<DagFunc>,
}

#[derive(Debug)]
pub struct Dag {}

impl Dag {
    // Manual serialization of the DAG, where we literally add a newline
    // after each keyword
    fn serialize_dag(dag: &DagGraph) -> Vec<u8> {
        let mut serialized = Vec::new();

        for func in &dag.funcs {
            serialized.extend(func.name.as_bytes());
            serialized.push(b'\n');

            serialized.extend(func.scale.as_bytes());
            serialized.push(b'\n');

            if let Some(chains_to) = &func.chains_to {
                serialized.extend(chains_to.as_bytes());
            }
            serialized.push(b'\n');

            serialized.push(b'\n');
        }

        serialized
    }

    // Function to read DAG from YAML path and serialize it to a byte array that
    // we can upload
    fn read_yaml_and_serialize(file_path: &str) -> Vec<u8> {
        let mut file = File::open(file_path).expect("tlessctl(dag): failed to load yaml path");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("tlessctl(dag): faild to read yaml");

        let dag: DagGraph =
            serde_yaml::from_str(&contents).expect("tlessctl(dag): failed to parse yaml");
        Self::serialize_dag(&dag)
    }

    // Return the hex-string of the hash of the serialized dag
    fn hash_serialized_dag(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();

        // Convert hash result to hex string
        hex::encode(result)
    }

    pub async fn upload(wflow_name: &str, yaml_path: &str) -> anyhow::Result<()> {
        // Load the given DAG to a byte array, and upload it to storage
        let serialized_dag = Self::read_yaml_and_serialize(yaml_path);
        S3::upload_bytes("tless", &format!("{wflow_name}/dag"), &serialized_dag).await;

        // Calculate the hexstring of the hash of the DAG, to make it one
        // of our attributes for CP-ABE
        let dag_hex_digest = Self::hash_serialized_dag(&serialized_dag);

        // Generate CP-ABE encryption context to encrypt code and data
        let (pk, msk) = rabe::schemes::bsw::setup();
        let ctx = rabe::ffi::bsw::CpAbeContext {
            _msk: msk.clone(),
            _pk: pk.clone(),
        };

        // Generate a serialized view of the CpAbeContext. This needs to be
        // unsafe as it needs to represent the raw underlying memory, because
        // we will have to re-construct the struct in C++ code
        let serial_ctx = unsafe {
            std::slice::from_raw_parts(
                (&ctx as *const rabe::ffi::bsw::CpAbeContext) as *const u8,
                std::mem::size_of::<rabe::ffi::bsw::CpAbeContext>(),
            )
        };

        // Get the key from the attestation service
        let tee_sym_key = attestation_service::get_tee_shared_key().await?;

        // Encrypt it with the shared symmetric key, so that any TEE can use
        // the CP-ABE encryption/decryption context
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&tee_sym_key));
        let ctx_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ctx_ct = cipher.encrypt(&ctx_nonce, serial_ctx).unwrap();
        let mut encrypted_ctx = ctx_nonce.to_vec();
        encrypted_ctx.extend_from_slice(&ctx_ct);

        // Serialize and upload context to S3
        S3::upload_bytes(
            "tless",
            &format!("{wflow_name}/crypto/cp-abe-ctx"),
            &encrypted_ctx,
        )
        .await;

        // Genesis text for our certificate chains
        // TODO: why do we need this again?
        let plain_text_origin_cert_chain = "G3N0SY5";

        // Base attributes for our policy
        let tee_identity_magic = attestation_service::get_tee_identity().await?;

        // Encrypt the certificate chain using the adequate policy
        // WARNING: be very careful with the values in the policy. rabe does
        // not like if attributes contain any non-alphanumeric characters
        let policy = format!("\"{}\" and \"{}\"", tee_identity_magic, dag_hex_digest);
        let ct = rabe::schemes::bsw::encrypt(
            &pk,
            &policy,
            rabe::utils::policy::pest::PolicyLanguage::HumanPolicy,
            plain_text_origin_cert_chain.as_bytes(),
        )
        .unwrap();

        let abe_ct_str = match serde_json::to_string(&ct) {
            Ok(ct_str) => ct_str,
            Err(_) => anyhow::bail!("error serializing certificate chain"),
        };

        // Encapsulate the cipher-text in a symmetric encryption payload
        let abe_ct_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let abe_ct = cipher
            .encrypt(&abe_ct_nonce, abe_ct_str.as_bytes())
            .unwrap();
        let mut encrypted_abe_ct = abe_ct_nonce.to_vec();
        encrypted_abe_ct.extend_from_slice(&abe_ct);

        // Upload the certificate chain for the first function
        // TODO: right now, they all ready from the same. Must update in
        // accordance with the DAG
        S3::upload_bytes(
            "tless",
            &format!("{wflow_name}/cert-chains/test"),
            &encrypted_abe_ct,
        )
        .await;

        // TODO(encrypted-functions): to support encrypted functions, here we
        // would have to keep generating new policies, and encrypting each
        // function body with the new policy

        Ok(())
    }
}
