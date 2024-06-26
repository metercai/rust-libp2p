use libp2p::{autonat, dcutr, mdns};
use libp2p::identify;
use libp2p::kad;
use libp2p::ping;
use libp2p::relay;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel, ProtocolSupport};
use libp2p::gossipsub::{self, IdentTopic, TopicHash};
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

use crate::req_resp;
use crate::config::ReqRespConfig;

const BOOTNODES: [&str; 2] = [
    "12D3KooWLjiAR9qyTBJwWgQAv3f4zaKW9iCTdQbm7skDLNa9st37",
    "12D3KooWCXCFdxdpBeXvzMgBGxyz9uD2GwYErsEsuTKxwaks7HCD",
];

pub(crate) const TOKEN_PROTO_NAME: StreamProtocol = StreamProtocol::new("/token/kad/1.0.0");

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    relay: Toggle<relay::Behaviour>,
    relay_client: Toggle<relay::client::Behaviour>,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub(crate) kademlia: kad::Behaviour<kad::store::MemoryStore>,
    mdns: Toggle<mdns::tokio::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
    pub(crate) pubsub: gossipsub::Behaviour,
    // `req_resp` is used for sending requests and responses.
    req_resp: request_response::Behaviour<req_resp::GenericCodec>,

}

impl Behaviour {
    pub(crate) fn new(
        local_key: identity::Keypair,
        relay_client: Option<relay::client::Behaviour>,
        is_global: bool,
        pubsub_topics: Vec<String>,
        req_resp_config: Option<ReqRespConfig>,
    ) -> Self {
        let pub_key = local_key.public();
        let kademlia = {
            let kademlia_config = kad::Config::new(TOKEN_PROTO_NAME);
            // Instantly remove records and provider records.
            // kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
            // kademlia_config.set_provider_record_ttl(Some(Duration::from_secs(0)));
            let kademlia = kad::Behaviour::with_config(
                pub_key.to_peer_id(),
                kad::store::MemoryStore::new(pub_key.to_peer_id()),
                kademlia_config,
            );
            kademlia
        };

        let is_relayserver = match relay_client {
            Some(ref _val) => false,
            None => true,
        };
        let relay = if is_relayserver {
            Some(relay::Behaviour::new(PeerId::from(pub_key.clone()), Default::default()))
        } else {
            None
        }.into();

        let mdns = if is_relayserver {
            None
        } else {
            Some(mdns::tokio::Behaviour::new(
                mdns::Config::default(), pub_key.clone().to_peer_id()).expect("Mdns service initialization failed！"))
        }.into();

        let dcutr = if is_relayserver {
            None
        } else {
            Some(dcutr::Behaviour::new(pub_key.clone().to_peer_id()))
        }.into();


        Self {
            relay,
            relay_client: relay_client.into(),
            ping: ping::Behaviour::new(ping::Config::default().with_interval(Duration::from_secs(15))),
            identify: identify::Behaviour::new(
                identify::Config::new("token/0.1.0".to_string(), pub_key.clone()).with_agent_version(
                    format!("p2pserver/{}", env!("CARGO_PKG_VERSION")),
                ),
            ),
            kademlia,
            mdns,
            dcutr,
            pubsub: Self::new_gossipsub(local_key, pubsub_topics),
            req_resp: Self::new_req_resp(req_resp_config),
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
            .heartbeat_initial_delay(Duration::from_millis(500))
            .heartbeat_interval(Duration::from_millis(5000))
            .history_length(10)
            .history_gossip(10)
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

    fn new_req_resp(config: Option<ReqRespConfig>) -> request_response::Behaviour<req_resp::GenericCodec> {
        if let Some(config) = config {
            return req_resp::BehaviourBuilder::new()
                //.with_connection_keep_alive(config.connection_keep_alive)
                .with_request_timeout(config.request_timeout)
                .with_max_request_size(config.max_request_size)
                .with_max_response_size(config.max_response_size)
                .build();
        }

        req_resp::BehaviourBuilder::default().build()
    }

    pub fn send_request(&mut self, target: &PeerId, request: Vec<u8>) -> OutboundRequestId {
        self.req_resp.send_request(target, request)
    }

    pub fn send_response(&mut self, ch: ResponseChannel<req_resp::ResponseType>, response: req_resp::ResponseType) {
        let _ = self.req_resp.send_response(ch, response);
    }

    pub(crate) fn discover_peers(&mut self) {
        if self.known_peers().is_empty() {
            tracing::info!("☕ Discovery process paused due to no boot node");
        } else {
            tracing::info!("☕ Starting a discovery process");
            let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.token.tm/tcp/2316").unwrap();
            for peer in &BOOTNODES {
            //    self.kademlia.add_address(&PeerId::from_str(peer).unwrap(), bootaddr.clone());
            }
            let _ = self.kademlia.bootstrap();
        }
    }

    pub(crate) fn known_peers(&mut self) -> HashMap<PeerId, Vec<Multiaddr>> {
        let mut peers = HashMap::new();
        for b in self.kademlia.kbuckets() {
            for e in b.iter() {
                peers.insert(*e.node.key.preimage(), e.node.value.clone().into_vec());
            }
        }
        peers
    }

    pub(crate) fn pubsub_peers(&mut self) -> HashMap<PeerId, Vec<TopicHash>> {
        let mut peers = HashMap::new();
        let mut peers_iter = self.pubsub.all_peers();
        while let Some((peer_id, topics)) = peers_iter.next() {
            let cloned_peer_id = (*peer_id).clone();
            let cloned_topics: Vec<TopicHash> = topics.iter().map(|topic| (*topic).clone()).collect();
            peers.insert(cloned_peer_id, cloned_topics);
        }
        peers
    }

    pub(crate) fn broadcast(&mut self, topic: String, message: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let topic = gossipsub::IdentTopic::new(topic);
        self.pubsub.publish(topic.clone(), message)?;
        tracing::info!("☕ =====>>>  Broadcast message to topic {}", topic);
        Ok(())
    }

    pub(crate) fn add_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        if can_add_to_dht(&addr) {
            tracing::info!("☕ Adding address {} from {:?} to the DHT.", addr, peer_id);
            self.kademlia.add_address(peer_id, addr);
        }
    }

    pub(crate) fn remove_peer(&mut self, peer_id: &PeerId) {
        tracing::info!("☕ Removing peer {} from the DHT.", peer_id);
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
