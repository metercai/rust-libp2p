use clap::Parser;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use std::thread;
use tracing_subscriber::EnvFilter;
use std::env;
use chrono::{Local, DateTime};
use tokio::time;
use openssl::rand::rand_bytes;

mod protocol;
mod http_service;
mod error;
mod utils;
mod service;
mod config;
mod req_resp;

use crate::service::{Client, EventHandler};

const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Parser)]
#[clap(name = "p2perver", about = "A rust-libp2p server binary.")]
struct Opts {
    /// Path to p2pserver config file.
    #[clap(long, default_value = "p2pconfig.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //env::set_var("RUST_LOG", "p2pserver=info");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let opt = Opts::parse();

    let config = config::Config::from_file(opt.config.as_path())?;

    let (client, mut server) = service::new(config.clone()).await?;
    server.set_event_handler(Handler);

    // Run the p2p server
    tokio::task::spawn(server.run());

    // Periodically print the node status.
    tokio::task::spawn(get_node_status(client.clone(), config.get_node_status_interval()));

    // Periodically send a request to one of the known peers.
    tokio::task::spawn(request(client.clone(), config.get_request_interval()));

    // Periodically make a broadcast to the network.
    broadcast(client.clone(), config.get_broadcast_interval());
    Ok(())
}


#[derive(Debug)]
struct Handler;

impl EventHandler for Handler {
    fn handle_inbound_request(&self, request: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        tracing::info!(
            "📣 <<<< Inbound request: {:?}",
            String::from_utf8_lossy(request.as_slice())
        );
        Ok(request)
    }

    fn handle_broadcast(&self, topic: &str, message: Vec<u8>) {
        tracing::info!(
            "📣 <<<< Inbound broadcast: {:?} {:?}",
            topic,
            String::from_utf8_lossy(message.as_slice())
        );
    }
}

async fn get_node_status(client: Client, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let node_status = client.get_node_status().await;
        let short_id = client.get_peer_id();
        tracing::info!("📣 {}", node_status.short_format());
    }
}

fn broadcast(client: Client, interval: u64) {
    let dur = Duration::from_secs(interval);
    loop {
        thread::sleep(dur);
        let topic = "system";
        let short_id = client.get_peer_id();
        let now_time = Local::now().format("%H:%M:%S.%f").to_string();
        let message = format!("Hello, a new block from {} at {}!", short_id, now_time);

        tracing::info!("📣 >>>> Outbound broadcast: {:?} {:?}", topic, message);
        let _ = client.broadcast(topic, message.as_bytes().to_vec());
    }
}

async fn request(client: Client, interval: u64) {
    let dur = time::Duration::from_secs(interval);
    loop {
        time::sleep(dur).await;
        let known_peers = client.get_known_peers().await;
        let short_id = client.get_peer_id();
        let mut random_bytes = [0u8; 1];
        rand_bytes(&mut random_bytes).unwrap();
        if known_peers.len()>0 {
            let random_index = random_bytes[0] as usize % known_peers.len();
            let target = &known_peers[random_index];
            let now_time = Local::now().format("%H:%M:%S.%4f").to_string();
            let target_id = target.chars().skip(target.len() - 7).collect::<String>();
            let request = format!("Hello {}, request from {} at {}!", target_id, short_id, now_time);
            tracing::info!("📣 >>>> Outbound request: {:?}", request);
            let response = client
                .request(target, request.as_bytes().to_vec()).await
                .unwrap();
            let now_time2 = Local::now().format("%H:%M:%S.%4f").to_string();
            tracing::info!(
            "📣 <<<< Inbound response: Time({}) {:?}", now_time2,
            String::from_utf8_lossy(&response)
            );
        }

    }
}

