use cloudevents::binding::reqwest::RequestBuilderExt;
use cloudevents::binding::warp::{filter, reply};
use cloudevents::{AttributesReader, AttributesWriter, Event};
use futures_util::StreamExt;
use minio::s3::args::*;
use minio::s3::client::ClientBuilder;
use minio::s3::creds::StaticProvider;
use minio::s3::error::Error;
use minio::s3::http::BaseUrl;
use minio::s3::types::ToStream;
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::{env, fs, thread, time};
use tokio::task::JoinHandle;
use warp::Filter;

// static BINARY_DIR: &str = "/workflows/build-native/ml-training";
static BINARY_DIR: &str = "/code/faasm-examples/workflows/build-native/ml-training"; // DELETE ME
static MERGE_INVOCATION_COUNTER: Lazy<Arc<Mutex<i64>>> = Lazy::new(|| Arc::new(Mutex::new(0)));
static WORKFLOW_NAME: &str = "ml-training(driver)";

struct S3Data {
    data: &'static str,
}

impl S3Data {
    // const HOST: S3Data = S3Data { data: "minio" };
    const HOST: S3Data = S3Data { data: "localhost" }; // DELETE ME - JUST TEST
    const PORT: S3Data = S3Data { data: "9000" };
    const USER: S3Data = S3Data { data: "minio" };
    const PASSWORD: S3Data = S3Data { data: "minio123" };
    const BUCKET: S3Data = S3Data { data: "tless" };
}

pub async fn wait_for_key(key_name: &str) {
    let base_url = format!("http://{}:{}", S3Data::HOST.data, S3Data::PORT.data)
        .parse::<BaseUrl>()
        .unwrap();

    let static_provider = StaticProvider::new(S3Data::USER.data, S3Data::PASSWORD.data, None);
    let client = ClientBuilder::new(base_url.clone())
        .provider(Some(Box::new(static_provider)))
        .build()
        .unwrap();

    // Return fast if the bucket does not exist
    let exists: bool = client
        .bucket_exists(&BucketExistsArgs::new(&S3Data::BUCKET.data).unwrap())
        .await
        .unwrap();

    if !exists {
        panic!(
            "{WORKFLOW_NAME}: waiting for key ({key_name}) in non-existant bucket: {}",
            S3Data::BUCKET.data
        );
    }

    // Loop until the object appears
    loop {
        let mut objects = client
            .list_objects(&S3Data::BUCKET.data)
            .recursive(true)
            .prefix(Some(key_name.to_string()))
            .to_stream()
            .await;

        while let Some(result) = objects.next().await {
            match result {
                Ok(_) => return,
                Err(e) => match e {
                    Error::S3Error(s3_error) => match s3_error.code.as_str() {
                        _ => panic!("{WORKFLOW_NAME}: error: {}", s3_error.message),
                    },
                    _ => panic!("{WORKFLOW_NAME}: error: {}", e),
                },
            }
        }

        thread::sleep(time::Duration::from_secs(2));
    }
}

// We must wait for the POST event to go through before we can return, as
// otherwise the chain may not make progress
pub fn post_event(dest: String, event: Event) -> JoinHandle<()> {
    tokio::spawn(async {
        reqwest::Client::new()
            .post(dest)
            .event(event)
            .map_err(|e| e.to_string())
            .unwrap()
            .header("Access-Control-Allow-Origin", "*")
            .send()
            .await
            .map_err(|e| e.to_string())
            .unwrap();
    })
}

pub fn get_json_from_event(event: &Event) -> Value {
    match event.data() {
        Some(cloudevents::Data::Json(json)) => Some(json.clone()),
        Some(cloudevents::Data::String(text)) => serde_json::from_str(&text).ok(),
        Some(cloudevents::Data::Binary(bytes)) => serde_json::from_slice(bytes).ok(),
        _ => panic!("tless(driver): error: must be json data"),
    }
    .unwrap()
}

// This function is a general wrapper that takes a cloud event as an input,
// decides what function to execute, and outputs another cloud event
pub fn process_event(mut event: Event) -> Event {
    // -----
    // Pre-process and function invocation
    // -----

    event.set_source(match event.source().as_str() {
        "cli" => {
            let func_name = "partition";
            println!("{WORKFLOW_NAME}: executing '{func_name}' from cli: {event}");

            let json = get_json_from_event(&event);
            let data_dir = json
                .get("data-dir")
                .and_then(Value::as_str)
                .expect("finra(driver): error: cannot find 'data-dir' in CE");

            let num_pca_funcs: i64 = get_json_from_event(&event)
                .get("num-pca-funcs")
                .and_then(Value::as_i64)
                .expect("finra(driver): error: cannot find 'num-pca-funcs' in CE");

            let num_train_funcs: i64 = get_json_from_event(&event)
                .get("num-train-funcs")
                .and_then(Value::as_i64)
                .expect("finra(driver): error: cannot find 'num-train-funcs' in CE");

            match Command::new(format!("{}/ml-training_{func_name}", BINARY_DIR))
                .current_dir(BINARY_DIR)
                .env("LD_LIBRARY_PATH", "/usr/local/lib")
                .env("S3_BUCKET", S3Data::BUCKET.data)
                .env("S3_HOST", S3Data::HOST.data)
                .env("S3_PASSWORD", S3Data::PASSWORD.data)
                .env("S3_PORT", S3Data::PORT.data)
                .env("S3_USER", S3Data::USER.data)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .arg(data_dir)
                .arg(num_pca_funcs.to_string())
                .arg(num_train_funcs.to_string())
                .output()
                .expect("finra(driver): error: spawning executing partition command")
                .status
                .code()
            {
                Some(0) => {
                    println!("{WORKFLOW_NAME}: '{func_name}' executed succesfully")
                }
                Some(code) => {
                    panic!("{WORKFLOW_NAME}: '{func_name}' failed with ec: {code}")
                }
                None => {
                    panic!("{WORKFLOW_NAME}: '{func_name}' failed")
                }
            }

            "partition"
        }
        "partition" => {
            let func_name = "pca";
            println!("{WORKFLOW_NAME}: executing '{func_name}' from partition: {event}");

            let pca_id: i64 = get_json_from_event(&event)
                .get("pca-id")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'pca-id' in CE");

            let num_pca_funcs: i64 = get_json_from_event(&event)
                .get("num-pca-funcs")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'num-train-funcs' in CE");

            let num_train_funcs: i64 = get_json_from_event(&event)
                .get("num-train-funcs")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'num-train-funcs' in CE");

            match Command::new(format!("{}/ml-training_{func_name}", BINARY_DIR))
                .current_dir(BINARY_DIR)
                .env("LD_LIBRARY_PATH", "/usr/local/lib")
                .env("S3_BUCKET", S3Data::BUCKET.data)
                .env("S3_HOST", S3Data::HOST.data)
                .env("S3_PASSWORD", S3Data::PASSWORD.data)
                .env("S3_PORT", S3Data::PORT.data)
                .env("S3_USER", S3Data::USER.data)
                .arg(pca_id.to_string())
                .arg(format!("ml-training/outputs/partition/pca-{pca_id}"))
                .arg(((num_train_funcs / num_pca_funcs) as i64).to_string())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .output()
                .expect("ml-training(driver): failed executing command")
                .status
                .code()
            {
                Some(0) => {
                    println!("{WORKFLOW_NAME}: '{func_name}' executed succesfully")
                }
                Some(code) => {
                    panic!("{WORKFLOW_NAME}: '{func_name}' failed with ec: {code}")
                }
                None => {
                    panic!("{WORKFLOW_NAME}: '{func_name}' failed")
                }
            }

            "pca"
        }
        "pca" => {
            let func_name = "rf";
            println!("{WORKFLOW_NAME}: executing '{func_name}' from 'pca': {event}");

            let pca_id: i64 = get_json_from_event(&event)
                .get("pca-id")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'pca-id' in CE");

            let rf_id: i64 = get_json_from_event(&event)
                .get("rf-id")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'rf-id' in CE");

            // Execute the function only after enough POST requests have
            // been received
            match Command::new(format!("{}/ml-training_{func_name}", BINARY_DIR))
                .current_dir(BINARY_DIR)
                .env("LD_LIBRARY_PATH", "/usr/local/lib")
                .env("S3_BUCKET", S3Data::BUCKET.data)
                .env("S3_HOST", S3Data::HOST.data)
                .env("S3_PASSWORD", S3Data::PASSWORD.data)
                .env("S3_PORT", S3Data::PORT.data)
                .env("S3_USER", S3Data::USER.data)
                .arg(pca_id.to_string())
                .arg(rf_id.to_string())
                .arg(format!("ml-training/outputs/pca-{pca_id}/rf-{rf_id}-data"))
                .arg(format!(
                    "ml-training/outputs/pca-{pca_id}/rf-{rf_id}-labels"
                ))
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .output()
                .expect("ml-training(driver): failed executing 'rf' command")
                .status
                .code()
            {
                Some(0) => {
                    println!("{WORKFLOW_NAME}: '{func_name}' executed succesfully")
                }
                Some(code) => {
                    panic!("{WORKFLOW_NAME}: '{func_name}' failed with ec: {code}")
                }
                None => {
                    panic!("{WORKFLOW_NAME}: '{func_name}' failed")
                }
            }

            "rf"
        }
        "rf" => {
            let func_name = "validation";
            println!("{WORKFLOW_NAME}: executing '{func_name}' from 'rf': {event}");

            let num_train_funcs: i64 = get_json_from_event(&event)
                .get("num-train-funcs")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'num-audit' in CE");

            let mut count = MERGE_INVOCATION_COUNTER.lock().unwrap();
            *count += 1;
            println!("${WORKFLOW_NAME}: counted {}/{}", *count, num_train_funcs);

            if *count == num_train_funcs {
                println!("${WORKFLOW_NAME}: done!");

                match Command::new(format!("{}/ml-training_{func_name}", BINARY_DIR))
                    .current_dir(BINARY_DIR)
                    .env("LD_LIBRARY_PATH", "/usr/local/lib")
                    .env("S3_BUCKET", S3Data::BUCKET.data)
                    .env("S3_HOST", S3Data::HOST.data)
                    .env("S3_PASSWORD", S3Data::PASSWORD.data)
                    .env("S3_PORT", S3Data::PORT.data)
                    .env("S3_USER", S3Data::USER.data)
                    .arg("ml-training/outputs/rf-")
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .output()
                    .expect("ml-training(driver): failed executing 'validation' command")
                    .status
                    .code()
                {
                    Some(0) => {
                        println!("{WORKFLOW_NAME}: '{func_name}' executed succesfully")
                    }
                    Some(code) => {
                        panic!("{WORKFLOW_NAME}: '{func_name}' failed with ec: {code}")
                    }
                    None => {
                        panic!("{WORKFLOW_NAME}: '{func_name}' failed")
                    }
                }

                // Reset counter for next (warm) execution
                println!("${WORKFLOW_NAME}: resetting counter to 0");
                *count = 0;
            }

            "validation"
        }
        _ => panic!(
            "{WORKFLOW_NAME}: error: unrecognised source: {:}",
            event.source()
        ),
    });

    // -----
    // Post-process
    // -----

    match event.source().as_str() {
        // Process the output of the 'partition' and chain to 'pca'
        "partition" => {
            let run_magic: i64 = get_json_from_event(&event)
                .get("run-magic")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'run-magic' in CE");

            let num_pca_funcs: i64 = get_json_from_event(&event)
                .get("num-pca-funcs")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'num-pca-funcs' in CE");

            let num_train_funcs: i64 = get_json_from_event(&event)
                .get("num-train-funcs")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'num-train-funcs' in CE");

            // This is the channel where PCA will post the CE too (given that
            // PCA is a JobSink)
            let mut scaled_event = event.clone();
            scaled_event.set_type("http://pca-to-rf-kn-channel.tless.svc.cluster.local");

            for i in 1..num_pca_funcs {
                scaled_event.set_id((run_magic + i).to_string());
                scaled_event.set_data(
                    "aplication/json",
                    json!({"pca-id": i, "num-train-funcs": num_train_funcs, "run-magic": run_magic, "num-pca-funcs": num_pca_funcs}),
                );

                println!(
                    "{WORKFLOW_NAME}: posting to {} event {i}/{num_pca_funcs}: {scaled_event}",
                    event.ty(),
                );
                post_event(event.ty().to_string(), scaled_event.clone());
            }

            // Update the event for the zero-th id (the one we return as part
            // of the method)
            scaled_event.set_id((run_magic + 0).to_string());
            scaled_event.set_data(
                "aplication/json",
                json!({"pca-id": 0, "num-train-funcs": num_train_funcs, "run-magic": run_magic, "num-pca-funcs": num_pca_funcs}),
            );

            scaled_event
        }
        // Process the output of the 'pca' function and chain to 'rf'
        "pca" => {
            let pca_id: i64 = get_json_from_event(&event)
                .get("pca-id")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'pca-id' in CE");

            let run_magic: i64 = get_json_from_event(&event)
                .get("run-magic")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'run-magic' in CE");

            let num_train_funcs: i64 = get_json_from_event(&event)
                .get("num-train-funcs")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'num-train-funcs' in CE");

            let num_pca_funcs: i64 = get_json_from_event(&event)
                .get("num-pca-funcs")
                .and_then(Value::as_i64)
                .expect("ml-training(driver): error: cannot find 'num-pca-funcs' in CE");

            // This is the channel where RF will post the CE to (given that
            // PCA is a JobSink)
            let mut scaled_event = event.clone();
            scaled_event.set_type("http://rf-to-validation-kn-channel.tless.svc.cluster.local");

            // Each PCA function chains to num_train_funcs / num_pca_funcs
            // functions to avoid a fan-in/fan-out pattern
            let this_func_scale: i64 = num_train_funcs / num_pca_funcs;
            println!("{WORKFLOW_NAME}: scaling to {this_func_scale} RF functions");

            for i in 1..this_func_scale {
                scaled_event.set_id((run_magic + i).to_string());
                scaled_event.set_data(
                    "aplication/json",
                    json!({"pca-id": pca_id, "rf-id": i, "num-train-funcs": num_train_funcs}),
                );

                println!(
                    "{WORKFLOW_NAME}: posting to {} event {i}/{this_func_scale}: {scaled_event}",
                    event.ty(),
                );
                post_event(event.ty().to_string(), scaled_event.clone());
            }

            // Update the event for the zero-th id (the one we return as part
            // of the method)
            scaled_event.set_id((run_magic + 0).to_string());
            scaled_event.set_data(
                "aplication/json",
                json!({"pca-id": pca_id, "rf-id": 0, "num-train-funcs": num_train_funcs}),
            );

            scaled_event
        }
        // Process the output of the 'rf' function and chain to 'validation'
        "rf" => {
            // The event already contains the number of traiing functions,
            // which is the fan-in that we need to wait-on, so we do nothing

            event
        }
        // Process the output of the 'validation' function
        "validation" => {
            // Nothing to do after "validation" as it is the last step in the chain
            event
        }
        _ => panic!(
            "{WORKFLOW_NAME}: error: unrecognised destination: {:}",
            event.source()
        ),
    }
}

#[tokio::main]
async fn main() {
    match env::var("CE_FROM_FILE") {
        Ok(value) => {
            assert!(value == "on");

            // This filepath is hard-coded in the JobSink specification:
            // https://knative.dev/docs/eventing/sinks/job-sink
            let file_contents = fs::read_to_string("/etc/jobsink-event/event").unwrap();
            let json_value = serde_json::from_str(&file_contents).unwrap();
            let event: Event = serde_json::from_value(json_value).unwrap();

            // The 'audit' function needs both the 'fetch-public' and
            // 'fetch-private' functions to execute before it can start. At
            // the same time, it is a JobSink, so it is invoked only once,
            // and not as a long-running HTTP server. As a consequence, we
            // cannot use our trick with the static shared counter. Instead,
            // we make sure both 'fetch-public' and 'fetch-private' only
            // trigger one job (using the same id), and here we wait for
            // both of them to finish
            let keys_to_wait = vec![
                "finra/outputs/fetch-public/trades",
                "finra/outputs/fetch-private/portfolio",
            ];
            for key_to_wait in keys_to_wait {
                println!("{WORKFLOW_NAME}: audit: waiting for key {key_to_wait}");
                wait_for_key(key_to_wait).await;
            }

            let processed_event = process_event(event);

            // After executing step-two, we just need to post a clone of the
            // event to the type (i.e. destination) provided in it. Given that
            // step-two runs in a JobSink, the pod will terminate on exit, so
            // we need to make sure that the POST is sent before we move on
            println!(
                "{WORKFLOW_NAME}: posting to {} event: {processed_event}",
                processed_event.ty()
            );
            post_event(processed_event.ty().to_string(), processed_event.clone())
                .await
                .unwrap();
        }
        Err(env::VarError::NotPresent) => {
            let routes = warp::any()
                // Extract event from request
                .and(filter::to_event())
                // Return the post-processed event
                .map(|event| reply::from_event(process_event(event)));

            warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
        }
        Err(e) => println!("Failed to read env. var: {}", e),
    };
}
