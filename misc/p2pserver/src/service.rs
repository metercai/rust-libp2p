use std::{
        cell::OnceCell,
        collections::HashMap,
        fmt::Debug,
        error::Error,
        str::FromStr,
        io,
        net::{Ipv4Addr, IpAddr},
        time::Duration };
use tokio::{
        select,
        sync::oneshot,
        time::{self, Interval},
        sync::mpsc::{self, UnboundedSender, UnboundedReceiver} };
use libp2p::{
        kad, tcp, identify, noise, yamux, ping,
        core::multiaddr::Protocol,
        identity::{Keypair, ed25519},
        futures::{StreamExt, FutureExt},
        metrics::{Metrics, Recorder},
        swarm::SwarmEvent,
        gossipsub::{self, TopicHash},
        request_response::{self, OutboundFailure, OutboundRequestId, ResponseChannel},
        Swarm, Multiaddr, PeerId,};

use prometheus_client::{metrics::info::Info, registry::Registry};
use zeroize::Zeroizing;

use crate::{http_service, utils};
use crate::protocol::*;
use crate::req_resp::*;
use crate::config::*;
use crate::error::P2pError;


const TOKEN_SERVER_IPADDR: &str = "0.0.0.0";
const TOKEN_SERVER_PORT: u16 = 2316;

/// `EventHandler` is the trait that defines how to handle requests / broadcast-messages from remote peers.
pub(crate) trait EventHandler: Debug + Send + 'static {
    /// Handles an inbound request from a remote peer.
    fn handle_inbound_request(&self, request: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
    /// Handles an broadcast message from a remote peer.
    fn handle_broadcast(&self, topic: &str, message: Vec<u8>);
}

#[derive(Clone, Debug)]
pub(crate) struct Client {
    cmd_sender: UnboundedSender<Command>,
    peer_id: String,
}

/// Create a new p2p node, which consists of a `Client` and a `Server`.
pub(crate) async fn new<E: EventHandler>(config: Config) -> Result<(Client, Server<E>), Box<dyn Error>> {
    let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
    let server = Server::new(config, cmd_receiver).await?;
    let local_peer_id = server.get_peer_id().to_base58();
    let client = Client {
        cmd_sender,
        peer_id: local_peer_id[local_peer_id.len() - 7..].to_string(),
    };

    Ok((client, server))
}

impl Client {
    /// Get the short peer id of the local node.
    pub fn get_peer_id(&self) -> String {
        self.peer_id.clone()
    }
    /// Send a blocking request to the `target` peer.
    pub async fn request(&self, target: &str, request: Vec<u8>) -> Result<Vec<u8>, P2pError> {
        let target = target.parse().map_err(|_| P2pError::InvalidPeerId)?;

        let (responder, receiver) = oneshot::channel();
        let _ = self.cmd_sender.send(Command::SendRequest {
            target,
            request,
            responder,
        });

        let response = receiver.await.map_err(|_| P2pError::RequestRejected)?;
        Ok(response?)
    }

    /// Publish a message to the given topic.
    pub(crate) async fn broadcast(&self, topic: impl Into<String>, message: Vec<u8>) {
        let _ = self.cmd_sender.send(Command::Broadcast {
            topic: topic.into(),
            message,
        });
    }

    /// Get known peers of the node.
    pub(crate) async fn get_known_peers(&self) -> Vec<String> {
        self.get_node_status().await
            .known_peers
            .into_keys()
            .map(|id| id.to_base58())
            .collect()
    }

    /// Get status of the node for debugging.
    // pub(crate) fn get_node_status(&self) -> NodeStatus {
    //     let (responder, receiver) = oneshot::channel();
    //     let _ = self.cmd_sender.send(Command::GetStatus(responder));
    //     receiver.blocking_recv().unwrap_or_default()
    // }

    pub async fn get_node_status(&self) -> NodeStatus {
        let (responder, receiver) = oneshot::channel();
        let _ = self.cmd_sender.send(Command::GetStatus(responder));
        receiver.await.unwrap_or_default()
    }
}

/// The commands sent by the `Client` to the `Server`.
pub(crate) enum Command {
    SendRequest {
        target: PeerId,
        request: Vec<u8>,
        responder: oneshot::Sender<ResponseType>,
    },
    Broadcast {
        topic: String,
        message: Vec<u8>,
    },
    GetStatus(oneshot::Sender<NodeStatus>),
}

pub(crate) struct Server<E: EventHandler> {
    /// The actual network service.
    network_service: Swarm<Behaviour>,
    /// The local peer id.
    local_peer_id: PeerId,
    /// The addresses that the server is listening on.
    listened_addresses: Vec<Multiaddr>,
    /// The receiver of commands from the client.
    cmd_receiver: UnboundedReceiver<Command>,
    /// The handler of events from remote peers.
    event_handler: OnceCell<E>,
    /// The ticker to periodically discover new peers.
    discovery_ticker: Interval,
    /// The pending outbound requests, awaiting for a response from the remote.
    pending_outbound_requests: HashMap<OutboundRequestId, oneshot::Sender<ResponseType>>,
    /// The topics will be hashed when subscribing to the gossipsub protocol,
    /// but we need to keep the original topic names for broadcasting.
    pubsub_topics: Vec<String>,
    metrics: Metrics,
}

impl<E: EventHandler> Server<E> {
    /// Create a new `Server`.
    pub(crate) async fn new(
        config: Config,
        cmd_receiver: UnboundedReceiver<Command>,
    ) -> Result<Self, Box<dyn Error>> {
        let mut metric_registry = Registry::default();
        let local_keypair  = Keypair::from(ed25519::Keypair::from(ed25519::SecretKey::
            try_from_bytes(Zeroizing::new(utils::read_key_or_generate_key()?))?));

        let announce = config.address.announce;
        let pubsub_topics: Vec<_> = config.pubsub_topics;
        let boot_nodes = config.address.boot_nodes;
        let req_resp_config = config.req_resp;

        let mut swarm = match announce.clone() {
            None => libp2p::SwarmBuilder::with_existing_identity(local_keypair.clone())
                .with_tokio()
                .with_tcp(
                    tcp::Config::default().port_reuse(true).nodelay(true),
                    noise::Config::new,
                    yamux::Config::default,
                )?
                .with_quic()
                .with_dns()?
                .with_relay_client(noise::Config::new, yamux::Config::default)?
                .with_bandwidth_metrics(&mut metric_registry)
                .with_behaviour(|key, relay_client| {
                    Behaviour::new(key.clone(), Some(relay_client), pubsub_topics.clone(), Some(req_resp_config.clone()))
                })?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                .build(),
            Some(_announce) => libp2p::SwarmBuilder::with_existing_identity(local_keypair.clone())
                .with_tokio()
                .with_tcp(
                    tcp::Config::default().port_reuse(true).nodelay(true),
                    noise::Config::new,
                    yamux::Config::default,
                )?
                .with_quic()
                .with_dns()?
                .with_bandwidth_metrics(&mut metric_registry)
                .with_behaviour(|key| {
                    Behaviour::new(key.clone(), None, pubsub_topics.clone(), Some(req_resp_config.clone()))
                })?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                .build(),
        };
        let ip_addrs = utils::get_local_ipaddr()?;
        let ip_addr = if ip_addrs.is_empty() {
            Ipv4Addr::UNSPECIFIED
        } else {
            ip_addrs[0]
        };
        let listen_ip: Multiaddr = config.address.listen;
        tracing::info!("P2PServer listen_ip: {}", listen_ip);
        let expected_listener_id = swarm
            .listen_on(listen_ip.clone().with(Protocol::Tcp(TOKEN_SERVER_PORT)))?;
        //.listen_on(Multiaddr::empty().with(Protocol::Ip4(Ipv4Addr::UNSPECIFIED)).with(Protocol::Tcp(TOKEN_SERVER_PORT)))?;
        tracing::info!("P2PServer listening on listener ID: {}", expected_listener_id);


        // let mut listen_addresses = 0;
        // while listen_addresses < 1 {
        //     if let SwarmEvent::NewListenAddr {
        //         listener_id,
        //         address,
        //     } = swarm.next().await.unwrap()
        //     {
        //         if listener_id == expected_listener_id {
        //             listen_addresses += 1;
        //         }
        //         tracing::info!("P2PServer ListenerId:{listener_id} Listening on {address} ");
        //     }
        // }

        let relay_addr = match boot_nodes {
            Some(boot_nodes) => {
                let boot_nodes_clone = boot_nodes.clone();
                for boot_node in boot_nodes.into_iter() {
                    swarm.behaviour_mut().add_address(&boot_node.peer_id(), boot_node.address());
                    tracing::info!("P2PServer boot_nodes: {boot_node}");
                    // swarm.behaviour_mut().auto_nat.add_server(&boot_node.peer_id(), boot_node.address());
                };
                Some(Multiaddr::from_str(format!("{}/p2p/{}", boot_nodes_clone[0].address(), boot_nodes_clone[0].peer_id()).as_str())?)
            }
            None => { None }
        };

        match announce.clone() {
            Some(announce) => {
                for address in announce.clone().into_iter() {
                    swarm.add_external_address(address.clone().into());
                }
                tracing::info!("External addresses: {:?}", announce)
            }
            None => match relay_addr {
                Some(relay_addr) => {
                    tracing::info!("P2PServer relay_addr: {:?}", relay_addr);
                    let id = swarm.listen_on(relay_addr.with(Protocol::P2pCircuit))?;
                    tracing::info!("P2PServer listenerid for relay: {:?}", id);
                }
                None => {}
            }
        }
        let listen_addrs = swarm.listeners();
        for addr in listen_addrs {
            tracing::info!("P2PServer start up: {}/p2p/{}", addr, swarm.local_peer_id());
        }
        swarm
            .behaviour_mut()
            .kademlia
            .set_mode(Some(kad::Mode::Server));
        swarm.behaviour_mut().discover_peers();

        let metrics = Metrics::new(&mut metric_registry);
        let build_info = Info::new(vec![("version".to_string(), env!("CARGO_PKG_VERSION"))]);
        metric_registry.register(
            "build",
            "A metric with a constant '1' value labeled by version",
            build_info,
        );

        tokio::task::spawn(async move {
            if let Err(e) = http_service::metrics_server(metric_registry, config.metrics_path).await {
                tracing::error!("Metrics server failed: {e}");
            }
        });



        // Create a ticker to periodically discover new peers.
        let interval_secs = config.discovery_interval;
        let instant = time::Instant::now() + Duration::from_secs(15);
        let discovery_ticker = time::interval_at(instant, Duration::from_secs(interval_secs));

        Ok(Self {
            network_service: swarm,
            local_peer_id: local_keypair.public().into(),
            listened_addresses: Vec::new(),
            cmd_receiver,
            event_handler: OnceCell::new(),
            discovery_ticker,
            pending_outbound_requests: HashMap::new(),
            pubsub_topics,
            metrics
        })
    }

    /// Set the handler of events from remote peers.
    pub(crate) fn set_event_handler(&mut self, handler: E) {
        self.event_handler.set(handler).unwrap();
    }

    /// Run the `Server`.
    pub(crate) async fn run(mut self) {
        loop {
            select! {
                // Next discovery process.
                _ = self.discovery_ticker.tick() => {
                    self.network_service.behaviour_mut().discover_peers();
                },

                // Next command from the `Client`.
                msg = self.cmd_receiver.recv() => {
                    if let Some(cmd) = msg {
                        self.handle_command(cmd);
                    }
                },
                // Next event from `Swarm`.
                event = self.network_service.select_next_some() => {
                    self.metrics.record(&event);
                    self.handle_swarm_event(event);
                },
            }

        }
    }

    // Process the next command coming from `Client`.
    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::SendRequest {
                target,
                request,
                responder,
            } => self.handle_outbound_request(target, request, responder),
            Command::Broadcast { topic, message } => self.handle_outbound_broadcast(topic, message),
            Command::GetStatus(responder) => responder.send(self.get_status()).unwrap(),
        }
    }
    // Process the next event coming from `Swarm`.
    fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        let behaviour_ev = match event {
            SwarmEvent::Behaviour(ev) => ev,

            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(%address, "📣 P2P node listening on address");
                return self.update_listened_addresses(); },

            SwarmEvent::ListenerClosed {
                reason, addresses, ..
            } => return Self::log_listener_close(reason, addresses),

            // Can't connect to the `peer`, remove it from the DHT.
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                ..
            } => return self.network_service.behaviour_mut().remove_peer(&peer),

            _ => return,
        };
        self.handle_behaviour_event(behaviour_ev);
    }

    fn handle_behaviour_event(&mut self, ev: BehaviourEvent) {
        tracing::info!("{:?}", ev);
        // self.metrics.record(&ev);
        match ev {
            // The remote peer is unreachable, remove it from the DHT.
            BehaviourEvent::Ping(ping::Event {
                peer,
                result: Err(_),
                ..
            }) => self.network_service.behaviour_mut().remove_peer(&peer),

            BehaviourEvent::Pubsub(gossipsub::Event::Message {
                propagation_source: peer_id,
                message_id: id,
                message,
            }) => {
                tracing::info!("Got broadcast message with id({id}) from peer({peer_id}): '{}'",
                        String::from_utf8_lossy(&message.data));
                self.handle_inbound_broadcast(message)
            },

            // See https://docs.rs/libp2p/latest/libp2p/kad/index.html#important-discrepancies
            BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info: identify::Info {
                    listen_addrs,
                    protocols,
                    .. },
            }) => {
                if protocols.iter().any(|p| *p == TOKEN_PROTO_NAME) {
                    self.add_addresses(&peer_id, listen_addrs);
                }
            } //self.add_addresses(&peer_id, listen_addrs),
            BehaviourEvent::ReqResp(request_response::Event::Message {
                message:
                request_response::Message::Request { request, channel, .. },
                ..
            }) => self.handle_inbound_request(request, channel),

            BehaviourEvent::ReqResp(request_response::Event::Message {
                message:
                request_response::Message::Response { request_id, response, },
                ..
            }) => self.handle_inbound_response(request_id, response),

            BehaviourEvent::ReqResp(request_response::Event::OutboundFailure {
                request_id,
                error,
                ..
            }) => self.handle_outbound_failure(request_id, error),

            _ => {}
        }
    }

    // Inbound requests are handled by the `EventHandler` which is provided by the application layer.
    fn handle_inbound_request(&mut self, request: Vec<u8>, ch: ResponseChannel<ResponseType>) {
        if let Some(handler) = self.event_handler.get() {
            let response = handler.handle_inbound_request(request).map_err(|_| ());
            self.network_service.behaviour_mut().send_response(ch, response);
        }
    }

    // Store the request_id with the responder so that we can send the response later.
    fn handle_outbound_request(
        &mut self,
        target: PeerId,
        request: Vec<u8>,
        responder: oneshot::Sender<ResponseType>,
    ) {
        let req_id = self
            .network_service
            .behaviour_mut()
            .send_request(&target, request);
        self.pending_outbound_requests.insert(req_id, responder);
    }

    // An outbound request failed, notify the application layer.
    fn handle_outbound_failure(&mut self, request_id: OutboundRequestId, error: OutboundFailure) {
        if let Some(responder) = self.pending_outbound_requests.remove(&request_id) {
            tracing::error!("❌ Outbound request failed: {:?}", error);
            let _ = responder.send(Err(()));
        } else {
            tracing::warn!("❗ Received failure for unknown request: {}", request_id);
            debug_assert!(false);
        }
    }

    // An inbound response was received, notify the application layer.
    fn handle_inbound_response(&mut self, request_id: OutboundRequestId, response: ResponseType) {
        if let Some(responder) = self.pending_outbound_requests.remove(&request_id) {
            let _ = responder.send(response);
        } else {
            tracing::warn!("❗ Received response for unknown request: {}", request_id);
            debug_assert!(false);
        }
    }

    // Inbound broadcasts are handled by the `EventHandler` which is provided by the application layer.
    fn handle_inbound_broadcast(&mut self, message: gossipsub::Message) {
        if let Some(handler) = self.event_handler.get() {
            let topic_hash = message.topic;
            match self.get_topic(&topic_hash) {
                Some(topic) => handler.handle_broadcast(&topic, message.data),
                None => {
                    tracing::warn!("❗ Received broadcast for unknown topic: {:?}", topic_hash);
                    debug_assert!(false);
                }
            }
        }
    }

    // Broadcast a message to all peers subscribed to the given topic.
    fn handle_outbound_broadcast(&mut self, topic: String, message: Vec<u8>) {
        let _ = self
            .network_service
            .behaviour_mut()
            .broadcast(topic, message);
    }

    fn add_addresses(&mut self, peer_id: &PeerId, addresses: Vec<Multiaddr>) {
        for addr in addresses.into_iter() {
            self.network_service
                .behaviour_mut()
                .add_address(peer_id, addr);
        }
    }

    fn get_status(&mut self) -> NodeStatus {
        let known_peers = self.network_service.behaviour_mut().known_peers();
        NodeStatus {
            local_peer_id: self.local_peer_id.to_base58(),
            listened_addresses: self.listened_addresses.clone(),
            known_peers_count: known_peers.len(),
            known_peers,
        }
    }

    fn get_peer_id(&self) -> PeerId {
        self.local_peer_id.clone()
    }

    fn update_listened_addresses(&mut self) {
        self.listened_addresses = self
            .network_service
            .listeners()
            .map(ToOwned::to_owned)
            .collect();
    }

    /// Returns the topic name for the given topic hash.
    fn get_topic(&self, topic_hash: &TopicHash) -> Option<String> {
        for t in &self.pubsub_topics {
            let topic = gossipsub::IdentTopic::new(t);
            if topic.hash() == *topic_hash {
                return Some(t.clone());
            }
        }
        None
    }

    fn log_listener_close(reason: io::Result<()>, addresses: Vec<Multiaddr>) {
        let addrs = addresses
            .into_iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        match reason {
            Ok(()) => {
                tracing::info!("📣 Listener ({}) closed gracefully", addrs)
            }
            Err(e) => {
                tracing::error!("❌ Listener ({}) closed: {}", addrs, e)
            }
        }
    }
}

/// The node status, for debugging.
#[derive(Clone, Debug, Default)]
pub(crate) struct NodeStatus {
    pub(crate) local_peer_id: String,
    pub(crate) listened_addresses: Vec<Multiaddr>,
    pub(crate) known_peers_count: usize,
    pub(crate) known_peers: HashMap<PeerId, Vec<Multiaddr>>,
}
