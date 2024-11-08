use axum::{routing::post, Router};
use clap::Parser;
use dotenvy::dotenv;
use events::handle_message_received;
use karak_rs::p2p::GossipMessage;
use libp2p::Multiaddr;
use p2p::{p2p_init, parse_bootstrap_nodes};
use rusqlite::Connection;
use server::{query_payloads, AppState};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing_error::ErrorLayer;
use tracing_subscriber::{layer::SubscriberExt, FmtSubscriber};
use wormhole_operator::{
    constants::TOPIC, events::run_event_listener, register::register_operator, utils::load_config,
    WormholeOperator, WormholeOperatorCommand,
};

pub use wormhole_operator::{constants, contracts, error, events, keypair, p2p, server, table};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv().ok();

    let cli = WormholeOperator::parse();

    //tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish()
        .with(ErrorLayer::default());

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    match cli.command {
        WormholeOperatorCommand::Run { .. } => {
            let config = load_config(cli).await?;
            let connection =
                Arc::new(Mutex::new(Connection::open(config.clone().env_config.db_path)?));
            let connection_clone = connection.clone();

            let config_clone = config.clone();

            // p2p
            let (_termination_signal, termination_receiver) = oneshot::channel::<()>();
            let (message_sender, message_receiver) = mpsc::channel::<GossipMessage<String>>(100);
            let p2p_handle = tokio::spawn(async move {
                let connection = connection_clone.clone();
                let bootstrap_nodes =
                    parse_bootstrap_nodes(config.env_config.bootstrap_nodes.clone()).unwrap();
                p2p_init(
                    TOPIC,
                    config.env_config.p2p_listen_address.parse::<Multiaddr>().unwrap(),
                    bootstrap_nodes,
                    termination_receiver,
                    message_receiver,
                    config.env_config.idle_timeout_duration,
                    move |_peer_id, _message_id, message| {
                        let connection = connection.clone();
                        let config = config.clone();
                        async move {
                            handle_message_received(message, &connection, config).await;
                        }
                    },
                )
                .await
                .unwrap();
            });

            // axum server
            let state = Arc::new(AppState {
                db: connection.clone(),
                config: Arc::new(Mutex::new(config_clone.clone())),
            });
            let app: Router =
                Router::new().route("/query_payloads", post(query_payloads)).with_state(state);
            let server_handle = tokio::spawn(async move {
                let addr = SocketAddr::from(([0, 0, 0, 0], config_clone.env_config.server_port));
                let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                let server1 = axum::serve(listener, app.into_make_service());
                tracing::info!("Server is listening on {}", addr);
                if let Err(e) = server1.await {
                    tracing::error!("Server 1 error: {}", e);
                }
            });

            let event_listener_handle = tokio::spawn(async move {
                run_event_listener(config_clone, &connection, &message_sender, TOPIC)
                    .await
                    .unwrap_or_else(|e| panic!("Run event listeners failed {}", e));
            });

            let joined_handles = tokio::join!(server_handle, p2p_handle, event_listener_handle);
            joined_handles.0.unwrap();
            joined_handles.1.unwrap();
            joined_handles.2.unwrap();
        }
        WormholeOperatorCommand::Register => {
            register_operator(cli).await?;
        }
    }
    Ok(())
}
