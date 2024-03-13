use clap::Parser;
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use std::thread;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;
use libp2p::identity::{ed25519::SecretKey, Keypair};
use std::collections::HashMap;
use std::env;

mod protocol;
mod http_service;
mod error;
mod utils;
mod service;
mod config;

use crate::service::{Client, EventHandler};

const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Parser)]
#[clap(name = "p2perver", about = "A rust-libp2p server binary.")]
struct Opts {
    /// Path to p2pserver config file.
    #[clap(long, default_value = "../p2pconfig.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env::set_var("RUST_LOG", "info");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let opt = Opts::parse();
    let key_bytes = utils::read_key_or_generate_key()?;
    println!("local key bytes: {:?}",key_bytes);
    let key = SecretKey::try_from_bytes(key_bytes)?;
    println!("local key: {:?}",key);

    let config = config::Config::from_file(opt.config.as_path())?;

    let (client, mut server) = service::new(config).await?;
    server.set_event_handler(Handler);

    // Run the p2p server
    tokio::task::spawn(server.run());

    // Periodically print the node status.
    let client_clone = client.clone();
    thread::spawn(move || get_node_status(client_clone));

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

fn get_node_status(client: Client) {
    let dur = Duration::from_secs(17);
    loop {
        thread::sleep(dur);
        let node_status = client.get_node_status();
        tracing::info!("📣 Node status: {:?}", node_status);
    }
}

fn broadcast(client: Client) {
    let dur = Duration::from_secs(13);
    loop {
        thread::sleep(dur);
        let topic = "block";
        let message = "Hello, a new block!";
        tracing::info!("📣 >>>> Outbound broadcast: {:?} {:?}", topic, message);
        let _ = client.broadcast(topic, message.as_bytes().to_vec());
    }
}

