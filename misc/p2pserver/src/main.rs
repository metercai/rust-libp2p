use clap::Parser;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use std::thread;
use tracing_subscriber::EnvFilter;
use std::env;
use chrono::{Local, DateTime};
use tokio::time;
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
    // env::set_var("RUST_LOG", "info");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let opt = Opts::parse();

    let config = config::Config::from_file(opt.config.as_path())?;

    let (client, mut server) = service::new(config).await?;
    server.set_event_handler(Handler);

    // Run the p2p server
    tokio::task::spawn(server.run());

    // Periodically print the node status.
    tokio::task::spawn(get_node_status(client.clone()));

    // Periodically send a request to one of the known peers.
    //tokio::task::spawn(request(client.clone()));

    // Periodically make a broadcast to the network.
    broadcast(client);
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

async fn get_node_status(client: Client) {
    let dur = time::Duration::from_secs(25);
    loop {
        time::sleep(dur).await;
        let node_status = client.get_node_status().await;
        let short_id = client.get_peer_id();
        let now_time = Local::now().format("%H:%M:%S").to_string();
        tracing::info!("📣 Node({}) status: {:?}", short_id, node_status);
    }
}

fn broadcast(client: Client) {
    let dur = Duration::from_secs(53);
    loop {
        thread::sleep(dur);
        let topic = "blocks";
        let short_id = client.get_peer_id();
        let now_time = Local::now().format("%H:%M:%S").to_string();
        let message = format!("Hello, a new block from {} at {}!", short_id, now_time);

        tracing::info!("📣 >>>> Outbound broadcast: {:?} {:?}", topic, message);
        let _ = client.broadcast(topic, message.as_bytes().to_vec());
    }
}

async fn request(client: Client) {
    let dur = time::Duration::from_secs(35);
    loop {
        time::sleep(dur).await;
        let known_peers = client.get_known_peers().await;
        if known_peers.len() > 0 {
            let target = &known_peers[0];
            let short_id = client.get_peer_id();
            let now_time = Local::now().format("%H:%M:%S").to_string();
            let request = format!("Hello, request from {} at {}!", short_id, now_time);

            tracing::info!("📣 >>>> Outbound request: {:?}", request);
            let response = client
                .request(target, request.as_bytes().to_vec()).await
                .unwrap();
            let now_time2 = Local::now().format("%H:%M:%S").to_string();
            tracing::info!(
                "📣 <<<< Inbound response: Time({}) {:?}", now_time2,
                String::from_utf8_lossy(&response)
            );
        }
    }
}

