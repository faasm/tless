use futures_util::StreamExt;
use minio::s3::args::*;
use minio::s3::builders::ObjectContent;
use minio::s3::client::{Client, ClientBuilder};
use minio::s3::creds::StaticProvider;
use minio::s3::http::BaseUrl;
use minio::s3::types::{S3Api, ToStream};
use std::path::Path;
use std::{env, fs};

#[derive(Debug)]
pub struct S3 {}

impl S3 {
    fn init_s3_client() -> Client {
        let minio_url: &str = match env::var("MINIO_URL") {
            Ok(value) => &value.clone(),
            Err(env::VarError::NotPresent) => "localhost",
            Err(e) => panic!("invrs(s3): failed to read env. var: {}", e),
        };
        let minio_port: &str = match env::var("MINIO_PORT") {
            Ok(value) => &value.clone(),
            Err(env::VarError::NotPresent) => "9000",
            Err(e) => panic!("invrs(s3): failed to read env. var: {}", e),
        };

        let base_url = format!("http://{minio_url}:{minio_port}")
            .parse::<BaseUrl>()
            .unwrap();

        let static_provider = StaticProvider::new("minio", "minio123", None);

        ClientBuilder::new(base_url.clone())
            .provider(Some(Box::new(static_provider)))
            .build()
            .unwrap()
    }

    pub async fn clear_bucket(bucket_name: String) {
        println!("invrs(s3): removing s3 bucket: {bucket_name}");

        // First, remove all objects in the bucket
        let client = Self::init_s3_client();

        // Return fast if the bucket does not exist
        let exists: bool = client
            .bucket_exists(&BucketExistsArgs::new(&bucket_name).unwrap())
            .await
            .unwrap();

        if !exists {
            println!("invrs(s3): skipping non-existant bucket: {bucket_name}");
            return;
        }

        let mut objects = client
            .list_objects(&bucket_name)
            .recursive(true)
            .to_stream()
            .await;

        while let Some(result) = objects.next().await {
            match result {
                Ok(resp) => {
                    for item in resp.contents {
                        client
                            .remove_object(&bucket_name, item.name.as_str())
                            .send()
                            .await
                            .unwrap();
                    }
                }
                Err(e) => println!("invrs(s3): error: {:?}", e),
            }
        }

        client
            .remove_bucket(&RemoveBucketArgs::new(&bucket_name).unwrap())
            .await
            .unwrap();
    }

    pub async fn clear_dir(bucket_name: String, prefix: String) {
        println!("invrs(s3): clearing s3 dir: {bucket_name}/{prefix}");

        // First, remove all objects in the bucket
        let client = Self::init_s3_client();

        // Return fast if the bucket does not exist
        let exists: bool = client
            .bucket_exists(&BucketExistsArgs::new(&bucket_name).unwrap())
            .await
            .unwrap();

        if !exists {
            println!("invrs(s3): warning: bucket does not exist: {bucket_name}");
            return;
        }

        let mut objects = client
            .list_objects(&bucket_name)
            .recursive(true)
            .prefix(Some(prefix))
            .to_stream()
            .await;

        while let Some(result) = objects.next().await {
            match result {
                Ok(resp) => {
                    for item in resp.contents {
                        client
                            .remove_object(&bucket_name, item.name.as_str())
                            .send()
                            .await
                            .unwrap();
                    }
                }
                Err(e) => println!("invrs(s3): error: {:?}", e),
            }
        }
    }

    pub async fn list_buckets() {
        let buckets = Self::init_s3_client().list_buckets().send().await.unwrap();

        println!(
            "invrs(s3): found a total of {} buckets",
            buckets.buckets.len()
        );
        for bucket in &buckets.buckets {
            println!("- {}", bucket.name);
        }
    }

    pub async fn list_keys(bucket_name: String) {
        println!("invrs(s3): listing keys in bucket {bucket_name}");

        let mut objects = Self::init_s3_client()
            .list_objects(&bucket_name)
            .recursive(true)
            .to_stream()
            .await;

        while let Some(result) = objects.next().await {
            match result {
                Ok(resp) => {
                    for item in resp.contents {
                        println!("- {:?}", item.name);
                    }
                }
                Err(e) => println!("invrs(s3): error: {:?}", e),
            }
        }
    }

    pub async fn upload_dir(bucket_name: String, host_path: String, s3_path: String) {
        println!("invrs(s3): uploading {host_path} to {bucket_name}/{s3_path}");

        let client = Self::init_s3_client();

        let exists: bool = client
            .bucket_exists(&BucketExistsArgs::new(&bucket_name).unwrap())
            .await
            .unwrap();

        if !exists {
            client
                .make_bucket(&MakeBucketArgs::new(&bucket_name).unwrap())
                .await
                .unwrap();
        }

        // Iterate over the host directory and upload each file therein
        let path = Path::new(&host_path);
        for entry in fs::read_dir(path).unwrap() {
            let host_file_path: &Path = &entry.unwrap().path();
            let content = ObjectContent::from(host_file_path);
            let s3_file_path = format!(
                "{}/{}",
                s3_path,
                host_file_path.file_name().expect("").to_string_lossy()
            );

            client
                .put_object_content(&bucket_name, &s3_file_path, content)
                .send()
                .await
                .unwrap();
        }
    }
}
