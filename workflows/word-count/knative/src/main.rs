use cloudevents::binding::reqwest::RequestBuilderExt;
use cloudevents::binding::warp::{filter, reply};
use cloudevents::{AttributesReader, AttributesWriter, Event};
use serde_json::{json, Value};
use std::process::{Command, Stdio};
use std::{cell::RefCell, env, fs, io::BufRead, io::BufReader};
use tokio::task::JoinHandle;
use warp::Filter;

static BINARY_DIR: &str = "/code/faasm-examples/workflows/build-native/word-count";
thread_local! {
    static S3_COUNTER: RefCell<i64> = const { RefCell::new(0) };
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

// This function is a general wrapper that takes a cloud event as an input,
// decides what function to execute, and outputs another cloud event
pub fn process_event(mut event: Event) -> Event {
    // -----
    // Pre-process and function invocation
    // -----

    event.set_source(match event.source().as_str() {
        "cli" => {
            println!("cloudevent: executing 'splitter' from cli: {event}");

            Command::new(format!("{}/word-count_splitter", BINARY_DIR))
                .current_dir(BINARY_DIR)
                .env("LD_LIBRARY_PATH", "/usr/local/lib")
                .env("S3_BUCKET", "tless")
                .env("S3_HOST", "minio")
                .env("S3_PASSWORD", "minio123")
                .env("S3_PORT", "9000")
                .env("S3_USER", "minio")
                .env("TLESS_S3_DIR", "word-count/few-files")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .output()
                .expect("tless(driver): failed executing command");

            "splitter"
        }
        "splitter" => {
            println!("cloudevent: executing 'mapper' from 'splitter': {event}");

            let json_file = match event.data() {
                Some(cloudevents::Data::Json(json)) => Some(json.clone()),
                Some(cloudevents::Data::Binary(bytes)) => serde_json::from_slice(bytes).ok(),
                _ => panic!("must be json data"),
            }
            .unwrap();
            let s3_file = json_file
                .get("input-file")
                .and_then(Value::as_str)
                .expect("foo");

            // Simulate actual function execution by a sleep
            Command::new(format!("{}/word-count_mapper", BINARY_DIR))
                .current_dir(BINARY_DIR)
                .env("LD_LIBRARY_PATH", "/usr/local/lib")
                .env("S3_BUCKET", "tless")
                .env("S3_HOST", "localhost")
                .env("S3_PASSWORD", "minio123")
                .env("S3_PORT", "9000")
                .env("S3_USER", "minio")
                .env("TLESS_S3_FILE", s3_file)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .output()
                .expect("tless(driver): failed executing command");

            "mapper"
        }
        "mapper" => {
            println!("cloudevent: executing 'reducer' from 'mapper': {event}");

            let json_file = match event.data() {
                Some(cloudevents::Data::Json(json)) => Some(json.clone()),
                Some(cloudevents::Data::Binary(bytes)) => serde_json::from_slice(bytes).ok(),
                _ => panic!("must be json data"),
            }
            .unwrap();
            let fan_out_scale = json_file
                .get("scale-factor")
                .and_then(Value::as_i64)
                .expect("foo");

            S3_COUNTER.with(|counter| {
                *counter.borrow_mut() += 1;
                println!(
                    "cloudevent(s3): counted {}/{}",
                    counter.borrow(),
                    fan_out_scale
                );

                if *counter.borrow() == fan_out_scale {
                    println!("cloudevent(s3): done!");
                }
            });

            // Execute the function only after enough POST requests have been
            // received
            Command::new(format!("{}/word-count_reducer", BINARY_DIR))
                .current_dir(BINARY_DIR)
                .env("LD_LIBRARY_PATH", "/usr/local/lib")
                .env("S3_BUCKET", "tless")
                .env("S3_HOST", "localhost")
                .env("S3_PASSWORD", "minio123")
                .env("S3_PORT", "9000")
                .env("S3_USER", "minio")
                .env(
                    "TLESS_S3_RESULTS_DIR",
                    "word-count/few-files/mapper-results",
                )
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .output()
                .expect("tless(reducer): failed executing command");

            "reducer"
        }
        _ => panic!(
            "cloudevent: error: unrecognised source: {:}",
            event.source()
        ),
    });

    // -----
    // Post-process
    // -----

    match event.source().as_str() {
        // Process the output of the 'splitter' function and chain to 'mapper'
        "splitter" => {
            // Read the output file to work-out the scale-out pattern and the
            // files to chain-to
            let mut lines: Vec<String> = Vec::new();
            let file = fs::File::open(format!("{}/{}", BINARY_DIR, "output_splitter.txt")).unwrap();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                lines.push(line.unwrap());
            }

            // Store the destinattion channel
            let dst = event.ty();

            let mut scaled_event = event.clone();

            // Write the new destination channel for the 'mapper' function
            scaled_event.set_type("http://mapper-to-reducer-kn-channel.tless.svc.cluster.local");

            println!("cloudevent(s1): fanning out by a factor of {}", lines.len());

            for i in 1..lines.len() {
                scaled_event.set_id(i.to_string());
                scaled_event.set_data(
                    "aplication/json",
                    json!({"scale-factor": lines.len(), "input-file": lines[i]}),
                );

                println!(
                    "cloudevent(s1): posting to {dst} event {i}/{}: {scaled_event}",
                    lines.len()
                );
                post_event(dst.to_string(), scaled_event.clone());
            }

            // Return the last event through the HTTP respnse
            scaled_event.set_id("0");
            scaled_event.set_data(
                "aplication/json",
                json!({"scale-factor": lines.len(), "input-file": lines[0]}),
            );
            scaled_event
        }
        // Process the output of the 'mapper' function and chain to 'reducer'
        "mapper" => {
            // We still need to POST the event manually but we need to do
            // it outside this method to be able to await on it (this method,
            // itself, is being await-ed on when called in a server loop)

            event
        }
        // Process the output of the 'redcuer' function
        "reducer" => {
            // Nothing to do after "reducer" as it is the last step in the chain

            event
        }
        _ => panic!(
            "cloudevent: error: unrecognised destination: {:}",
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

            let processed_event = process_event(event);

            // After executing step-two, we just need to post a clone of the
            // event to the type (i.e. destination) provided in it. Given that
            // step-two runs in a JobSink, the pod will terminate on exit, so
            // we need to make sure that the POST is sent before we move on
            println!(
                "cloudevent(s2): posting to {} event: {processed_event}",
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
