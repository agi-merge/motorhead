use actix_web::{error, middleware, web, App, HttpResponse, HttpServer};
use std::collections::HashMap;
use std::{fs::File, io::BufReader};
use std::env;
use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
mod healthcheck;
mod long_term_memory;
mod memory;
mod models;
mod redis_utils;
mod reducer;
mod retrieval;

use healthcheck::get_health;
use memory::{delete_memory, get_memory, post_memory};
use models::AppState;
use redis_utils::ensure_redisearch_index;
use retrieval::run_retrieval;

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting Motörhead 🤘");

    let openai_client = async_openai::Client::new();
    let redis_url = env::var("REDIS_URL").expect("$REDIS_URL is not set");
    let redis = redis::Client::open(redis_url).unwrap();

    let long_term_memory = env::var("MOTORHEAD_LONG_TERM_MEMORY")
        .map(|value| value.to_lowercase() == "true")
        .unwrap_or(false);

    if long_term_memory {
        // TODO: Make these configurable - for now just ADA support
        let vector_dimensions = 1536;
        let distance_metric = "COSINE";

        ensure_redisearch_index(&redis, vector_dimensions, distance_metric).unwrap_or_else(|err| {
            eprintln!("RediSearch index error: {}", err);
            std::process::exit(1);
        });
    }

    // /etc/letsencrypt/live/motorhead.waggledance.ai/privkey.pem
    let port = env::var("MOTORHEAD_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| 8080);

    let window_size = env::var("MOTORHEAD_MAX_WINDOW_SIZE")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or_else(|| 12);

    let session_cleanup = Arc::new(Mutex::new(HashMap::new()));
    let session_state = Arc::new(AppState {
        window_size,
        session_cleanup,
        openai_client,
        long_term_memory,
    });
    let key_path = env::var("TLS_PRIVATE_KEY_PATH").expect("$TLS_PRIVATE_KEY_PATH is not set");
    let cert_path = env::var("TLS_CERTIFICATE_PATH").expect("$TLS_CERTIFICATE_PATH is not set");

    let tls_config: rustls::ServerConfig = load_rustls_config(cert_path, key_path);
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(redis.clone()))
            .app_data(web::Data::new(session_state.clone()))
            .wrap(middleware::Logger::default())
            .service(get_health)
            .service(get_memory)
            .service(post_memory)
            .service(delete_memory)
            .service(run_retrieval)
            .app_data(web::JsonConfig::default().error_handler(|err, _req| {
                error::InternalError::from_response(
                    "",
                    HttpResponse::BadRequest()
                        .content_type("application/json")
                        .body(format!(r#"{{"error":"{}"}}"#, err)),
                )
                .into()
            }))
    })
    .bind_rustls(format!("0.0.0.0:{}", port), tls_config)?
    .run()
    .await
}


fn load_rustls_config(cert_path: String, key_path: String) -> rustls::ServerConfig {

    // load TLS key/cert files

    let cert_file = &mut BufReader::new(File::open(cert_path).unwrap());

    let key_file = &mut BufReader::new(File::open(key_path).unwrap());

    // convert files to key/cert objects
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();
    // exit if no keys could be parsed
    if keys.is_empty() {

        eprintln!("No PKCS8 private keys found. Trying PKCS1 format.");
        // let key_file = &mut BufReader::new(File::open(&key_path).unwrap());
        keys = rsa_private_keys(key_file)
            .unwrap()
            .into_iter()
            .map(PrivateKey)
            .collect();

        if keys.is_empty() {
            eprintln!("No PKCS1 private keys found. Exiting.");
            std::process::exit(1);
        }
    }

    let private_key = keys.remove(0);
    // init server config builder with safe defaults

    let config = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
         .with_safe_default_kx_groups()
         .with_safe_default_protocol_versions()
         .unwrap()
         .with_no_client_auth();


    config.with_single_cert(cert_chain, private_key).unwrap()
}