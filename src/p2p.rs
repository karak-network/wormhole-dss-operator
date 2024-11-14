use futures::Future;
use karak_rs::p2p::{GossipMessage, KarakP2P, P2PNode};
use libp2p::{
    gossipsub::{Message, MessageId},
    Multiaddr, PeerId,
};
use tokio::sync::{mpsc, oneshot};

pub async fn p2p_init<M, F, Fut>(
    topic: &str,
    listen_addr: Multiaddr,
    bootstrap_addrs: Vec<P2PNode>,
    termination_receiver: oneshot::Receiver<()>,
    message_receiver: mpsc::Receiver<GossipMessage<M>>,
    idle_timeout_duration: u64,
    on_incoming_message: F,
) -> eyre::Result<()>
where
    M: AsRef<[u8]> + Send + 'static,
    F: Fn(PeerId, MessageId, Message) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    let mut karak_p2p = KarakP2P::create_and_start_swarm(
        topic,
        listen_addr,
        bootstrap_addrs,
        termination_receiver,
        message_receiver,
        idle_timeout_duration,
    )?;

    tracing::info!("peer id: {}", karak_p2p.peer_id());

    karak_p2p.start_listening(on_incoming_message).await?;
    Ok(())
}

pub fn parse_bootstrap_nodes(input: &str) -> eyre::Result<Vec<P2PNode>> {
    let input =
        input.trim().trim_start_matches("BOOTSTRAP_NODES=").trim_matches('[').trim_matches(']');
    input
        .split("},")
        .map(|node_str| {
            let node_str = node_str.trim().trim_matches('{').trim_matches('}');
            let mut parts = node_str.split(',');

            let peer_id = parts
                .next()
                .and_then(|s| s.split(':').nth(1))
                .ok_or("Missing peer_id")
                .map_err(|e| eyre::eyre!("Failed to parse peer id: {}", e))?
                .trim()
                .trim_matches('"')
                .parse::<PeerId>()?;

            let address = parts
                .next()
                .and_then(|s| s.split(':').nth(1))
                .ok_or("Missing address")
                .map_err(|e| eyre::eyre!("Failed to parse address: {}", e))?
                .trim()
                .trim_matches('"')
                .parse::<Multiaddr>()?;

            Ok(P2PNode { peer_id, address })
        })
        .collect()
}
