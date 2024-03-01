use libp2p::{autonat, dcutr, mdns};
use libp2p::identify;
use libp2p::kad;
use libp2p::ping;
use libp2p::relay;
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::{NetworkBehaviour, StreamProtocol};
use libp2p::{identity, Multiaddr, PeerId};
use std::str::FromStr;
use std::time::Duration;
use std::hash::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;

const BOOTNODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    relay: Toggle<relay::Behaviour>,
    relay_client: Toggle<relay::client::Behaviour>,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub(crate) kademlia: Toggle<kad::Behaviour<kad::store::MemoryStore>>,
    autonat: Toggle<autonat::Behaviour>,
    mdns: mdns::tokio::Behaviour,
    dcutr: dcutr::Behaviour,
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
            Some(kademlia)
        }.into();

        let autonat = match relay_client {
            Some(ref val) => Some(autonat::Behaviour::new(PeerId::from(pub_key.clone()), Default::default())),
            None => None,
        }.into();

        let relay: Option<relay::Behaviour> = match relay_client {
            Some(ref val) => Some(relay::Behaviour::new(PeerId::from(pub_key.clone()), Default::default())),
            None => None,
        }.into();

        Self {
            relay: relay.into(),
            relay_client: relay_client.into(),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new("ipfs/0.1.0".to_string(), pub_key.clone()).with_agent_version(
                    format!("rust-libp2p-server/{}", env!("CARGO_PKG_VERSION")),
                ),
            ),
            kademlia,
            autonat,
            mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), pub_key.clone().to_peer_id()).expect("mdns inital failed!"),
            dcutr: dcutr::Behaviour::new(pub_key.clone().to_peer_id()),
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
}
