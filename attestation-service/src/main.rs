use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use hyper::server::conn::http1;
use hyper_util::{rt::tokio::TokioIo, service::TowerToHyperService};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VcekResponse {
    vcek_cert: String,
    certificate_chain: String,
}

pub fn fetch_vcek_pem() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let resp: VcekResponse = ureq::get("http://169.254.169.254/metadata/THIM/amd/certification")
        .set("Metadata", "true")
        .call()?
        .into_json()?;

    let pem = format!("{}\n{}", resp.vcek_cert, resp.certificate_chain);
    Ok(pem.into_bytes())
}

#[derive(Clone, Debug)]
struct AppState {
    pub vcek_pem: Vec<u8>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Preload or generate your state
    let vcek_pem = fetch_vcek_pem();
    let state = Arc::new(AppState {
        vcek_pem: vcek_pem.expect("as: failed to get vceck"),
    });

    let app = Router::new()
        .route("/process", post(process))
        .layer(Extension(state.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let listener = TcpListener::bind(addr).await;
    println!("Server running on {}", addr);

    loop {
        let (stream, _) = listener.as_ref().expect("error listening").accept().await?;
        let io = TokioIo::new(stream);
        let service = TowerToHyperService::new(app.clone());

        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Server connection error: {:?}", err);
            }
        });
    }
}

async fn process(Extension(state): Extension<Arc<AppState>>, body: Body) -> impl IntoResponse {
    // Convert raw body to Bytes
    let full_body = to_bytes(body, 1024 * 1024).await;

    match full_body {
        Ok(bytes) => {
            // Simulated task: here we just reverse the bytes
            match snpguest::verify::attestation::verify_attestation(&state.vcek_pem, bytes.as_ref())
            {
                Ok(_) => (StatusCode::OK, "attestation report verified"),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "attestation report verification failed",
                ),
            }
        }
        Err(_) => (StatusCode::BAD_REQUEST, "Invalid body".into()),
    }
}
