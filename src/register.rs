use crate::{
    contracts::ContractManager,
    keypair::{get_wallet_provider, prompt_load_keypair, sign_hash},
    utils::{ChainConfig, ChainConfigData, JsonChainConfig},
    Bn254Kms, EthKms, WormholeOperator,
};
use alloy::{
    primitives::{Address, Bytes},
    providers::{Provider, WalletProvider},
    sol_types::SolValue,
};
use dotenvy::dotenv;
use eyre::Result;
use karak_rs::{
    contracts::Core::CoreInstance,
    kms::keypair::{bn254::bls::registration::BlsRegistration, traits::Keypair},
};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct EnvConfig {
    pub bn254_keystore_method: Bn254Kms,
    pub bn254_key_path: Option<String>,
    pub bn254_keystore_password: Option<String>,
    pub bn254_aws_access_key_id: Option<String>,
    pub bn254_aws_secret_access_key: Option<String>,
    pub bn254_aws_default_region: Option<String>,
    pub bn254_aws_key_name: Option<String>,
    pub bn254_aws_password: Option<String>,
    pub eth_kms: EthKms,
    pub eth_keystore_password: Option<String>,
    pub eth_private_key: Option<String>,
    pub eth_keystore_path: Option<String>,
    pub eth_aws_access_key_id: Option<String>,
    pub eth_aws_secret_access_key: Option<String>,
    pub eth_aws_region: Option<String>,
    pub eth_aws_key_name: Option<String>,
}

async fn parse_chain_config(
    chain_config_data: ChainConfigData,
    env_config: &EnvConfig,
) -> Result<ChainConfig> {
    let ws_provider = get_wallet_provider(
        env_config.eth_kms,
        env_config.eth_private_key.clone(),
        env_config.eth_keystore_path.clone(),
        env_config.eth_keystore_password.clone(),
        env_config.eth_aws_access_key_id.clone(),
        env_config.eth_aws_secret_access_key.clone(),
        env_config.eth_aws_region.clone(),
        env_config.eth_aws_key_name.clone(),
        chain_config_data.ws_rpc_url.clone(),
    )
    .await?;

    let wormhole_dss_contract_manager = ContractManager::new(
        chain_config_data.wormhole_dss_address.parse::<Address>()?,
        ws_provider.clone(),
    )
    .await?;

    let core_instance =
        CoreInstance::new(chain_config_data.core_address.parse::<Address>()?, ws_provider.clone());

    Ok(ChainConfig {
        wormhole_chain_id: chain_config_data.wormhole_chain_id,
        wormhole_dss_manager: wormhole_dss_contract_manager,
        ws_rpc_provider: ws_provider,
        core_instance,
        listen: chain_config_data.listen,
    })
}

pub async fn register_operator(cli: WormholeOperator) -> Result<()> {
    dotenv().ok();

    let mut config = EnvConfig {
        bn254_keystore_method: cli.bn254_kms,
        bn254_key_path: cli.bn254_keystore_path,
        bn254_keystore_password: None,
        bn254_aws_access_key_id: cli.bn254_aws_access_key_id,
        bn254_aws_secret_access_key: cli.bn254_aws_secret_access_key,
        bn254_aws_default_region: cli.bn254_aws_default_region,
        bn254_aws_key_name: cli.bn254_aws_key_name,
        bn254_aws_password: None,
        eth_kms: cli.eth_kms,
        eth_keystore_password: None,
        eth_private_key: cli.eth_private_key,
        eth_keystore_path: cli.eth_keystore_path,
        eth_aws_access_key_id: cli.eth_aws_access_key_id,
        eth_aws_secret_access_key: cli.eth_aws_secret_access_key,
        eth_aws_region: cli.eth_aws_region,
        eth_aws_key_name: cli.eth_aws_key_name,
    };

    let json_chain_config: JsonChainConfig =
        serde_json::from_str(&std::fs::read_to_string("config.json")?)?;

    if Bn254Kms::Local == config.bn254_keystore_method {
        config.bn254_keystore_password =
            Some(rpassword::prompt_password("Please enter password for bn254 keystore: ").unwrap());
    }
    if Bn254Kms::Aws == config.bn254_keystore_method {
        config.bn254_aws_password =
            Some(rpassword::prompt_password("Please enter password for aws keystore: ").unwrap());
    }
    if EthKms::Local == config.eth_kms {
        config.eth_keystore_password =
            Some(rpassword::prompt_password("Please enter password for eth keystore: ").unwrap());
    }

    let keypair = prompt_load_keypair(
        config.bn254_keystore_method,
        config.bn254_key_path.clone(),
        config.bn254_keystore_password.clone(),
        config.bn254_aws_access_key_id.clone(),
        config.bn254_aws_secret_access_key.clone(),
        config.bn254_aws_default_region.clone(),
        config.bn254_aws_key_name.clone(),
        config.bn254_aws_password.clone(),
    )
    .await?;

    for chain_config in json_chain_config.chains {
        if chain_config.listen {
            let keypair_clone = keypair.clone();
            let chain_data = parse_chain_config(chain_config, &config).await?;

            let operator_address = chain_data.ws_rpc_provider.wallet().default_signer().address();

            tracing::info!(
                "Registering operator {} with Wormhole DSS on chain_id {}",
                operator_address,
                chain_data.wormhole_chain_id
            );
            let bls_registration = BlsRegistration {
                g1_pubkey: keypair_clone.public_key().g1,
                g2_pubkey: keypair_clone.public_key().g2,
                signature: sign_hash(
                    Bytes::from(
                        chain_data
                            .wormhole_dss_manager
                            .wormhole_dss_instance
                            .REGISTRATION_MESSAGE_HASH()
                            .call()
                            .await?
                            ._0,
                    ),
                    keypair_clone,
                ),
            };

            let is_operator_registered = chain_data
                .core_instance
                .isOperatorRegisteredToDSS(
                    operator_address,
                    *chain_data.wormhole_dss_manager.wormhole_dss_instance.address(),
                )
                .call()
                .await?
                ._0;

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let nonce = chain_data.ws_rpc_provider.get_transaction_count(operator_address).await?;
            tracing::info!(
                "Operator is already registered on chain {}: {}",
                chain_data.wormhole_chain_id,
                is_operator_registered
            );
            if !is_operator_registered {
                chain_data
                    .core_instance
                    .registerOperatorToDSS(
                        *chain_data.wormhole_dss_manager.wormhole_dss_instance.address(),
                        bls_registration.abi_encode().into(),
                    )
                    .nonce(nonce)
                    .send()
                    .await?
                    .get_receipt()
                    .await?;
                tracing::info!(
                    "Operator registered Successfully on chain {}: {}",
                    chain_data.wormhole_chain_id,
                    is_operator_registered
                );
            }
        }
    }

    Ok(())
}
