use std::{str::FromStr, sync::Arc};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, Bytes, Signature},
};
use base64::prelude::*;
use ethers_core::{abi, types::H160};
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
use tracing;

use crate::{
    contracts::WormholeDSS::WormholeDSSMessageSent,
    keypair::{self, g1_point_from_bytes_string, get_operator_signed_message, G1PointAffine},
    table::{create_tables, insert_payload},
    utils::{from_wormhole_format, Config},
    EventSubscriptionMode,
};

#[derive(Clone)]
pub struct DssContext {
    keypair: bn254::Keypair,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct WormholeMessage {
    pub message_event: String,
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
    pub message_event: String,
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
    config: Arc<Config>,
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

    // create tables
    create_tables(connection).await?;

    let mode = match config.env_config.event_subscription_mode {
        EventSubscriptionMode::Latest => BlockNumberOrTag::Latest,
        EventSubscriptionMode::Safe => BlockNumberOrTag::Safe,
        EventSubscriptionMode::Finalized => BlockNumberOrTag::Finalized,
    };

    let dss_context = Arc::new(dss_context);
    let mut futures = FuturesUnordered::new();

    for (chain_id, chain_config) in config.chain_config.chains.clone() {
        if chain_config.listen {
            let stream = chain_config
                .wormhole_dss_manager
                .wormhole_dss_instance
                .WormholeDSSMessageSent_filter()
                .from_block(mode)
                .subscribe()
                .await
                .wrap_err(format!("Failed to create message filter for chain {}", chain_id))?;

            let dss_context_for_chain_future = dss_context.clone();
            let config_for_chain_future = config.clone();

            let chain_future = async move {
                let mut event_stream = stream.into_stream();
                while let Some(result) = event_stream.next().await {
                    match result {
                        Ok((log, _)) => {
                            handle_event_log_message_published(
                                dss_context_for_chain_future.clone(),
                                &log,
                                chain_id,
                                &connection,
                                &message_sender,
                                topic,
                                config_for_chain_future.clone()
                            )
                            .await?;
                        }
                        Err(e) => {
                            tracing::error!(
                                "Error receiving log message on chain {}: {}",
                                chain_id,
                                e
                            );
                            continue;
                        }
                    }
                }
                Ok::<_, eyre::Error>(())
            };
            futures.push(chain_future);
        }
    }

    while let Some(result) = futures.next().await {
        if let Err(e) = result {
            tracing::error!("Chain stream processing error: {}", e);
        }
    }

    Ok(())
}

pub async fn handle_event_log_message_published(
    dss_context: Arc<DssContext>,
    event: &WormholeDSSMessageSent,
    src_chain_id: u16,
    connection: &Arc<Mutex<Connection>>,
    message_sender: &mpsc::Sender<GossipMessage<String>>,
    topic: &str,
    config: Arc<Config>,
) -> eyre::Result<()> {
    tracing::info!("Received event: {} on chain {}", event.message, src_chain_id);

    let abi_encoded_message: Bytes = abi::encode(&[
        abi::Token::Address(H160::from_str(event.caller.to_string().as_str())?),
        abi::Token::Uint(ethers_core::types::U256::from(event.sourceChain)),
        abi::Token::Uint(ethers_core::types::U256::from(event.recipientChain)),
        abi::Token::FixedBytes(event.sourceNttManager.to_vec()),
        abi::Token::FixedBytes(event.recipientNttManager.to_vec()),
        abi::Token::FixedBytes(event.refundAddress.to_vec()),
        abi::Token::Bytes(event.message.clone().to_vec()),
    ])
    .into();

    tracing::info!("ABI encoded message payload: {}", abi_encoded_message);

    let signed_payload = keypair::sign(&abi_encoded_message, &dss_context.keypair)?;

    tracing::info!("Signed payload: {}", signed_payload);

    let (operator_address, operator_signature) = get_operator_signed_message(
        &abi_encoded_message.to_string(),
        config.env_config.eth_keystore_method,
        config.env_config.eth_private_key.clone(),
        config.env_config.eth_keypair_path.clone(),
        config.env_config.eth_keystore_password.clone(),
        config.env_config.eth_aws_access_key_id.clone(),
        config.env_config.eth_aws_secret_access_key.clone(),
        config.env_config.eth_aws_region.clone(),
        config.env_config.eth_aws_key_name.clone(),
    )
    .await?;

    let operator_data = OperatorData {
        src_chain_id,
        dst_chain_id: event.recipientChain,
        message_event: event.message.to_string(),
        signed_payload: signed_payload.clone(),
        unsigned_payload: abi_encoded_message.clone(),
        bls_public_key_g1: Bytes::from(dss_context.keypair.public_key().g1.to_bytes()?),
        bls_public_key_g2: Bytes::from(dss_context.keypair.public_key().g2.to_bytes()?),
        operator_address: operator_address.to_string(),
        operator_signature,
    };

    insert_payload(
        connection,
        &operator_data,
        from_wormhole_format(event.recipientNttManager)?.to_string(),
    )
    .await
    .unwrap_or_else(|e| {
        tracing::error!("Failed to insert payload: {}", e);
    });

    let wormhole_message = WormholeMessage {
        src_chain_id,
        dst_chain_id: event.recipientChain,
        message_event: event.message.to_string(),
        unsigned_payload: BASE64_STANDARD.encode(abi_encoded_message),
        signed_payload: BASE64_STANDARD.encode(signed_payload),
        bls_public_key_g2: BASE64_STANDARD.encode(dss_context.keypair.public_key().g2.to_bytes()?),
        bls_public_key_g1: BASE64_STANDARD.encode(dss_context.keypair.public_key().g1.to_bytes()?),
        operator_address: operator_address.to_string(),
        operator_signature: BASE64_STANDARD
            .encode(Bytes::from(operator_signature.as_bytes())),
        destination_ntt_manager: from_wormhole_format(event.recipientNttManager)?.to_string(),
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

    Ok(())
}

pub async fn handle_message_received(
    message: Message,
    connection: Arc<Mutex<Connection>>,
    config: Arc<Config>,
) -> eyre::Result<()> {
    let message_string = String::from_utf8_lossy(&message.data);
    let wormhole_message =
        WormholeMessage::from_base64(&message_string).expect("Failed to decode message");

    tracing::info!("Received message: {:?}", wormhole_message);

    let unsigned_payload =
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.unsigned_payload)?);
    let signed_payload =
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.signed_payload)?);
    let bls_public_key_g2 =
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.bls_public_key_g2)?);
    let bls_public_key_g1 =
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.bls_public_key_g1)?);
    let operator_address = wormhole_message.operator_address;
    let operator_signature = Signature::from_str(
        Bytes::from(BASE64_STANDARD.decode(wormhole_message.operator_signature)?)
            .to_string()
            .as_str(),
    )?;

    let operator_data = OperatorData {
        src_chain_id: wormhole_message.src_chain_id,
        dst_chain_id: wormhole_message.dst_chain_id,
        message_event: wormhole_message.message_event,
        signed_payload,
        unsigned_payload,
        bls_public_key_g1,
        bls_public_key_g2,
        operator_address,
        operator_signature,
    };

    if !verify_operator_and_registration(&operator_data, operator_signature, config).await? {
        tracing::error!("Verification of operator and registration failed");
        return Err(eyre::eyre!("Verification of operator and registration failed"));
    }

    insert_payload(
        &connection,
        &operator_data,
        wormhole_message.destination_ntt_manager,
    )
    .await
    .unwrap_or_else(|e| {
        tracing::error!("Failed to insert payload: {}", e);
    });

    Ok(())
}

async fn verify_operator_and_registration(
    operator_data: &OperatorData,
    operator_signature: Signature,
    config: Arc<Config>,
) -> eyre::Result<bool> {
    let dst_chain_config = config
        .chain_config
        .chains
        .get(&operator_data.dst_chain_id)
        .unwrap_or_else(|| panic!("Chain id {} not found", operator_data.dst_chain_id));

    let is_valid = keypair::verify(
        operator_data.signed_payload.to_owned(),
        operator_data.unsigned_payload.to_owned(),
        operator_data.bls_public_key_g2.to_owned()
    ) && keypair::verify_bls_keys(
        operator_data.bls_public_key_g1.to_owned(),
        operator_data.bls_public_key_g2.to_owned(),
        operator_data.signed_payload.to_owned(),
        operator_data.unsigned_payload.to_owned(),
    ) && operator_signature
        .recover_address_from_msg(operator_data.unsigned_payload.to_string().as_bytes())?
        == operator_data.operator_address.clone().parse::<Address>()?
        && dst_chain_config
            .wormhole_dss_manager
            .is_operator_registered(operator_data.operator_address.to_owned())
            .await?
        && dst_chain_config
            .wormhole_dss_manager
            .operator_address_matches_g1_key(
                operator_data.operator_address.to_owned(),
                <G1PointAffine>::from(g1_point_from_bytes_string(
                    operator_data.bls_public_key_g1.to_string(),
                )?),
            )
            .await?;

    Ok(is_valid)
}
