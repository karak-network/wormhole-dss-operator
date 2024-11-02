use std::{str::FromStr, sync::Arc};

use alloy::{
    dyn_abi::DynSolValue,
    eips::BlockNumberOrTag,
    primitives::{Address, Bytes, Signature, U256},
};
use base64::prelude::*;
use eyre::Context;
use futures::{stream::FuturesUnordered, StreamExt};
use karak_rs::{
    kms::keypair::{bn254, traits::Keypair},
    p2p::GossipMessage,
};
use libp2p::gossipsub::Message;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tracing::{self, info};

use crate::{
    contracts::WormholeDSS::WormholeDSSMessageSent,
    keypair::{self, g1_point_from_bytes_string, get_operator_signed_message, G1PointAffine},
    table::{create_tables, insert_payload},
    utils::{from_wormhole_format, Config},
};

#[derive(Clone)]
pub struct DssContext {
    keypair: bn254::Keypair,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct WormholeMessage {
    pub unsigned_payload: String,
    pub signed_payload: String,
    pub bls_public_key_g2: String,
    pub bls_public_key_g1: String,
    pub operator_address: String,
    pub operator_signature: String,
    pub src_chain_id: u16,
    pub dst_chain_id: u16,
    pub destination_ntt_manager: String,
}

pub struct OperatorData {
    pub src_chain_id: u16,
    pub dst_chain_id: u16,
    pub signed_payload: Bytes,
    pub unsigned_payload: Bytes,
    pub bls_public_key_g1: Bytes,
    pub bls_public_key_g2: Bytes,
    pub operator_address: String,
    pub operator_signature: Signature,
}

impl WormholeMessage {
    pub fn to_base64(&self) -> eyre::Result<String> {
        let json = serde_json::to_string(self)?;
        Ok(BASE64_STANDARD.encode(json))
    }

    pub fn from_base64(base64_string: &str) -> eyre::Result<Self> {
        let json = BASE64_STANDARD.decode(base64_string)?;
        let message: WormholeMessage = serde_json::from_slice(&json)?;
        Ok(message)
    }
}

pub async fn run_event_listener(
    config: Config,
    connection: &Arc<Mutex<Connection>>,
    message_sender: &mpsc::Sender<GossipMessage<String>>,
    topic: &str,
) -> eyre::Result<()> {
    let keypair = keypair::prompt_load_keypair(
        config.env_config.bn254_keystore_method,
        config.env_config.bn254_key_path.clone(),
        config.env_config.bn254_keystore_password.clone(),
        config.env_config.bn254_aws_access_key_id.clone(),
        config.env_config.bn254_aws_secret_access_key.clone(),
        config.env_config.bn254_aws_default_region.clone(),
        config.env_config.bn254_aws_key_name.clone(),
        config.env_config.bn254_aws_password.clone(),
    )
    .await?;
    let dss_context = DssContext { keypair };
    create_tables(&mut connection.clone()).await?;

    let mode = match config.env_config.event_subscription_mode.clone().as_str() {
        "LATEST" => BlockNumberOrTag::Latest,
        "SAFE" => BlockNumberOrTag::Safe,
        _ => BlockNumberOrTag::Safe,
    };

    let mut futures = FuturesUnordered::new();

    // Clone necessary values before the loop
    let connection = connection.clone();
    let message_sender = message_sender.clone();
    let topic = topic.to_string();
    let dss_context = Arc::new(dss_context);

    for (chain_id, chain_config) in config.chain_config.chains.clone() {
        let stream = chain_config
            .wormhole_dss_manager
            .wormhole_dss_instance
            .WormholeDSSMessageSent_filter()
            .from_block(mode)
            .subscribe()
            .await
            .wrap_err(format!("Failed to create message filter for chain {}", chain_id))?;

        // Clone the values needed for the async closure
        let connection = connection.clone();
        let message_sender = message_sender.clone();
        let topic = topic.clone();
        let config = config.clone();
        let dss_context = dss_context.clone();

        let chain_future = async move {
            let mut event_stream = stream.into_stream();
            while let Some(result) = event_stream.next().await {
                match result {
                    Ok((log, _)) => {
                        handle_event_log_message_published(
                            (*dss_context).clone(),
                            &log,
                            chain_id,
                            &connection,
                            &message_sender,
                            &topic,
                            config.clone(),
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::error!("Error receiving log message on chain {}: {}", chain_id, e);
                        continue;
                    }
                }
            }
            Ok::<_, eyre::Error>(())
        };
        futures.push(chain_future);
    }

    while let Some(result) = futures.next().await {
        if let Err(e) = result {
            tracing::error!("Chain stream processing error: {}", e);
        }
    }

    Ok(())
}

pub async fn handle_event_log_message_published(
    dss_context: DssContext,
    event: &WormholeDSSMessageSent,
    src_chain_id: u16,
    connection: &Arc<Mutex<Connection>>,
    message_sender: &mpsc::Sender<GossipMessage<String>>,
    topic: &String,
    config: Config,
) {
    let abi_encoded_message = Bytes::from(
        DynSolValue::Tuple(vec![
            DynSolValue::Address(event.caller),
            DynSolValue::Uint(U256::from(event.sourceChain), 16),
            DynSolValue::Uint(U256::from(event.recipientChain), 16),
            DynSolValue::FixedBytes(event.sourceNttManager, 32),
            DynSolValue::FixedBytes(event.recipientNttManager, 32),
            DynSolValue::FixedBytes(event.refundAddress, 32),
            DynSolValue::Bytes(event.message.clone().into()),
        ])
        .abi_encode(),
    );
    tracing::info!("ABI encoded message: {}", abi_encoded_message);
    let signed_payload = keypair::sign(abi_encoded_message.clone(), dss_context.keypair.clone());

    let (operator_address, operator_signature) = get_operator_signed_message(
        abi_encoded_message.to_string(),
        config.env_config.eth_keystore_method,
        config.env_config.eth_private_key.clone(),
        config.env_config.eth_keypair_path.clone(),
        config.env_config.eth_keystore_password.clone(),
        config.env_config.eth_aws_access_key_id.clone(),
        config.env_config.eth_aws_secret_access_key.clone(),
        config.env_config.eth_aws_region.clone(),
        config.env_config.eth_aws_key_name.clone(),
    )
    .await;

    insert_payload(
        connection,
        OperatorData {
            src_chain_id,
            dst_chain_id: event.recipientChain,
            signed_payload: signed_payload.clone(),
            unsigned_payload: abi_encoded_message.clone(),
            bls_public_key_g1: Bytes::from(dss_context.keypair.public_key().g1.to_bytes().unwrap()),
            bls_public_key_g2: Bytes::from(dss_context.keypair.public_key().g2.to_bytes().unwrap()),
            operator_address: operator_address.to_string(),
            operator_signature,
        },
        from_wormhole_format(event.recipientNttManager).unwrap().to_string(),
    )
    .await
    .unwrap_or_else(|e| {
        tracing::error!("Failed to insert payload: {}", e);
    });
    // broadcast to all other peers
    let wormhole_message = WormholeMessage {
        src_chain_id,
        dst_chain_id: event.recipientChain,
        unsigned_payload: BASE64_STANDARD.encode(abi_encoded_message.clone()),
        signed_payload: BASE64_STANDARD.encode(signed_payload.clone()),
        bls_public_key_g2: BASE64_STANDARD
            .encode(dss_context.keypair.public_key().g2.to_bytes().unwrap()),
        bls_public_key_g1: BASE64_STANDARD
            .encode(dss_context.keypair.public_key().g1.to_bytes().unwrap()),
        operator_address: operator_address.clone().to_string(),
        operator_signature: BASE64_STANDARD
            .encode(Bytes::from(operator_signature.clone().as_bytes())),
        destination_ntt_manager: from_wormhole_format(event.recipientNttManager)
            .unwrap()
            .to_string(),
    };

    message_sender
        .send(GossipMessage::new(
            topic.to_owned(),
            wormhole_message.to_base64().expect("Failed to encode message"),
        ))
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to send message: {}", e);
        });

    info!("Signed payload: {}", signed_payload);
}

pub async fn handle_message_received(
    message: Message,
    connection: &Arc<Mutex<Connection>>,
    config: Config,
) {
    let message_string = String::from_utf8_lossy(&message.data);
    let wormhole_message =
        WormholeMessage::from_base64(&message_string).expect("Failed to decode message");

    let unsigned_payload =
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.unsigned_payload.clone()).unwrap());
    let signed_payload =
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.signed_payload.clone()).unwrap());
    let bls_public_key_g2 =
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.bls_public_key_g2.clone()).unwrap());
    let bls_public_key_g1 =
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.bls_public_key_g1.clone()).unwrap());
    let operator_address = wormhole_message.operator_address.clone();
    let operator_signature = Signature::from_str(
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.operator_signature.clone()).unwrap())
            .to_string()
            .as_str(),
    )
    .unwrap();

    if !verify_operator_and_registration(
        OperatorData {
            src_chain_id: wormhole_message.src_chain_id,
            dst_chain_id: wormhole_message.dst_chain_id,
            signed_payload: signed_payload.clone(),
            unsigned_payload: unsigned_payload.clone(),
            bls_public_key_g1: bls_public_key_g1.clone(),
            bls_public_key_g2: bls_public_key_g2.clone(),
            operator_address: operator_address.clone(),
            operator_signature,
        },
        operator_signature,
        config.clone(),
    )
    .await
    {
        tracing::error!("Verification of operator and registration failed");
        return;
    }

    insert_payload(
        connection,
        OperatorData {
            src_chain_id: wormhole_message.src_chain_id,
            dst_chain_id: wormhole_message.dst_chain_id,
            signed_payload: signed_payload.clone(),
            unsigned_payload: unsigned_payload.clone(),
            bls_public_key_g1: bls_public_key_g1.clone(),
            bls_public_key_g2: bls_public_key_g2.clone(),
            operator_address: operator_address.clone(),
            operator_signature,
        },
        wormhole_message.destination_ntt_manager,
    )
    .await
    .unwrap_or_else(|e| {
        tracing::error!("Failed to insert payload: {}", e);
    });
}

async fn verify_operator_and_registration(
    operator_data: OperatorData,
    operator_signature: Signature,
    config: Config,
) -> bool {
    let dst_chain_config = config
        .chain_config
        .chains
        .get(&operator_data.dst_chain_id)
        .unwrap_or_else(|| panic!("Chain id {} not found", operator_data.dst_chain_id));

    keypair::verify(
        operator_data.signed_payload.clone(),
        operator_data.unsigned_payload.clone(),
        operator_data.bls_public_key_g2.clone(),
    ) && keypair::verify_bls_keys(
        operator_data.bls_public_key_g1.clone(),
        operator_data.bls_public_key_g2.clone(),
        operator_data.signed_payload.clone(),
        operator_data.unsigned_payload.clone(),
    ) && operator_signature
        .recover_address_from_msg(operator_data.unsigned_payload.to_string().as_bytes())
        .unwrap()
        == operator_data.operator_address.clone().parse::<Address>().unwrap()
        && dst_chain_config
            .wormhole_dss_manager
            .is_operator_registered(operator_data.operator_address.clone())
            .await
            .unwrap()
        && dst_chain_config
            .wormhole_dss_manager
            .operator_address_matches_g1_key(
                operator_data.operator_address.clone(),
                <G1PointAffine>::from(g1_point_from_bytes_string(
                    operator_data.bls_public_key_g1.to_string(),
                )),
            )
            .await
            .unwrap()
}
