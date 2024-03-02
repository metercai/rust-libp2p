use libp2p::{autonat, dcutr, mdns};
use libp2p::identify;
use libp2p::kad;
use libp2p::ping;
use libp2p::relay;
use libp2p::multiaddr::Protocol;
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, StreamProtocol};
use libp2p::{identity, Multiaddr, PeerId};
use std::{
    str::FromStr,
    net::IpAddr,
    time::Duration,
    error::Error,
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
};



const BOOTNODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

pub(crate) type ResponseType = Result<Vec<u8>, ()>;

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    relay: Toggle<relay::Behaviour>,
    relay_client: Toggle<relay::client::Behaviour>,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub(crate) kademlia: kad::Behaviour<kad::store::MemoryStore>,
    autonat: autonat::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
    pubsub: gossipsub::Behaviour,
}

impl Behaviour {
    pub(crate) fn new(
        local_key: identity::Keypair,
        relay_client: Option<relay::client::Behaviour>,
        pubsub_topics: Vec<String>,
    ) -> Self {
        let pub_key = local_key.public();
        let kademlia = {
            let mut kademlia_config = kad::Config::new(IPFS_PROTO_NAME);
            // Instantly remove records and provider records.
            //
            // TODO: Replace hack with option to disable both.
            kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
            kademlia_config.set_provider_record_ttl(Some(Duration::from_secs(0)));
            let mut kademlia = kad::Behaviour::with_config(
                pub_key.to_peer_id(),
                kad::store::MemoryStore::new(pub_key.to_peer_id()),
                kademlia_config,
            );
            let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io").unwrap();
            for peer in &BOOTNODES {
                kademlia.add_address(&PeerId::from_str(peer).unwrap(), bootaddr.clone());
            }
            kademlia.bootstrap().unwrap();
            kademlia
        };

        let enable_outer = match relay_client {
            Some(ref _val) => false,
            None => true,
        };
        let relay = if enable_outer {
            Some(relay::Behaviour::new(PeerId::from(pub_key.clone()), Default::default()))
        } else {
            None
        }.into();

        let mdns = if enable_outer {
            None
        } else {
            Some(mdns::tokio::Behaviour::new(
                mdns::Config::default(), pub_key.clone().to_peer_id()).expect("Mdns service initialization failed！"))
        }.into();

        let dcutr = if enable_outer {
            None
        } else {
            Some(dcutr::Behaviour::new(pub_key.clone().to_peer_id()))
        }.into();

        Self {
            relay,
            relay_client: relay_client.into(),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new("ipfs/0.1.0".to_string(), pub_key.clone()).with_agent_version(
                    format!("rust-libp2p-server/{}", env!("CARGO_PKG_VERSION")),
                ),
            ),
            kademlia,
            autonat: autonat::Behaviour::new(PeerId::from(pub_key.clone()), Default::default()),
            mdns: mdns,
            dcutr: dcutr,
            pubsub: Self::new_gossipsub(local_key, pubsub_topics),
        }
    }

    fn new_gossipsub(
        local_key: identity::Keypair,
        topics: Vec<String>,
    ) -> gossipsub::Behaviour {
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            gossipsub::MessageId::from(s.finish().to_string())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .expect("Failed to create gossipsub configuration");

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key),
            gossipsub_config,
        ).expect("Failed to create gossipsub behaviour");

        for t in topics {
            let topic = IdentTopic::new(t);
            gossipsub.subscribe(&topic).expect("Failed to subscribe to topic");
        }
        gossipsub
    }

    pub fn discover_peers(&mut self) {
        if self.known_peers().is_empty() {
            tracing::debug!("☕ Discovery process paused due to no boot node");
        } else {
            tracing::debug!("☕ Starting a discovery process");
            let _ = self.kademlia.bootstrap();
        }
    }

    pub fn known_peers(&mut self) -> HashMap<PeerId, Vec<Multiaddr>> {
        let mut peers = HashMap::new();
        for b in self.kademlia.kbuckets() {
            for e in b.iter() {
                peers.insert(*e.node.key.preimage(), e.node.value.clone().into_vec());
            }
        }
        peers
    }
    pub fn broadcast(&mut self, topic: String, message: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let topic = gossipsub::IdentTopic::new(topic);
        self.pubsub.publish(topic, message)?;

        Ok(())
    }

    pub fn add_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        if can_add_to_dht(&addr) {
            tracing::debug!("☕ Adding address {} from {:?} to the DHT.", addr, peer_id);
            self.kademlia.add_address(peer_id, addr);
        }
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        tracing::debug!("☕ Removing peer {} from the DHT.", peer_id);
        self.kademlia.remove_peer(peer_id);
    }

}

fn can_add_to_dht(addr: &Multiaddr) -> bool {
    let ip = match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => IpAddr::V4(ip),
        Some(Protocol::Ip6(ip)) => IpAddr::V6(ip),
        Some(Protocol::Dns(_)) | Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => return true,
        _ => return false,
    };

    !ip.is_loopback() && !ip.is_unspecified()
}
