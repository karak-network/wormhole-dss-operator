use std::collections::HashMap;

use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{Address, FixedBytes, Uint, U160, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, RootProvider,
    },
    pubsub::PubSubFrontend,
};
use eyre::Result;
use karak_rs::contracts::Core::CoreInstance;
use serde::{Deserialize, Serialize};

use crate::{
    contracts::{ContractManager, RecommendedWalletProvider},
    keypair::get_wallet_provider,
    Bn254Kms, EthKms, EventSubscriptionMode, WormholeOperator, WormholeOperatorCommand,
};

#[derive(Debug, Deserialize, Clone)]
pub struct EnvConfig {
    pub p2p_listen_address: String,
    pub bootstrap_nodes: String,
    pub idle_timeout_duration: u64,
    pub event_subscription_mode: EventSubscriptionMode,
    pub bn254_keystore_method: Bn254Kms,
    pub bn254_key_path: Option<String>,
    pub bn254_keystore_password: Option<String>,
    pub bn254_aws_access_key_id: Option<String>,
    pub bn254_aws_secret_access_key: Option<String>,
    pub bn254_aws_default_region: Option<String>,
    pub bn254_aws_key_name: Option<String>,
    pub bn254_aws_password: Option<String>,
    pub eth_keystore_method: EthKms,
    pub eth_aws_access_key_id: Option<String>,
    pub eth_aws_secret_access_key: Option<String>,
    pub eth_aws_region: Option<String>,
    pub eth_aws_key_name: Option<String>,
    pub eth_keypair_path: Option<String>,
    pub eth_private_key: Option<String>,
    pub eth_keystore_password: Option<String>,
    pub db_path: String,
    pub server_port: u16,
}

#[derive(Clone)]
pub struct Config {
    pub env_config: EnvConfig,
    pub chain_config: ChainData,
}

type CoreInstanceType = CoreInstance<
    PubSubFrontend,
    FillProvider<
        JoinFill<
            JoinFill<
                Identity,
                JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
            >,
            WalletFiller<EthereumWallet>,
        >,
        RootProvider<PubSubFrontend>,
        PubSubFrontend,
        Ethereum,
    >,
>;

#[derive(Debug, Serialize, Deserialize)]
pub struct ChainConfigData {
    pub name: String,
    pub wormhole_chain_id: u16,
    pub wormhole_dss_address: String,
    pub core_address: String,
    pub ws_rpc_url: String,
    pub listen: bool,
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub wormhole_chain_id: u16,
    pub wormhole_dss_manager: ContractManager,
    pub core_instance: CoreInstanceType,
    pub ws_rpc_provider: RecommendedWalletProvider,
    pub listen: bool,
}

#[derive(Debug, Deserialize)]
pub struct JsonChainConfig {
    pub chains: Vec<ChainConfigData>,
}

#[derive(Clone)]
pub struct ChainData {
    pub chains: HashMap<u16, ChainConfig>,
}

async fn parse_chain_config(
    chain_config_data: ChainConfigData,
    env_config: &EnvConfig,
) -> Result<ChainConfig> {
    let ws_provider = get_wallet_provider(
        env_config.eth_keystore_method,
        env_config.eth_private_key.clone(),
        env_config.eth_keypair_path.clone(),
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

async fn get_chain_data(
    json_chain_config: JsonChainConfig,
    env_config: &mut EnvConfig,
) -> Result<ChainData> {
    let mut chain_hashmap: HashMap<u16, ChainConfig> = HashMap::new();

    if Bn254Kms::Local == env_config.bn254_keystore_method {
        env_config.bn254_keystore_password =
            Some(rpassword::prompt_password("Please enter password for bn254 keystore: ").unwrap());
    }
    if Bn254Kms::Aws == env_config.bn254_keystore_method {
        env_config.bn254_aws_password =
            Some(rpassword::prompt_password("Please enter password for aws keystore: ").unwrap());
    }
    if EthKms::Local == env_config.eth_keystore_method {
        env_config.eth_keystore_password =
            Some(rpassword::prompt_password("Please enter password for eth keystore: ").unwrap());
    }

    for chain_config in json_chain_config.chains {
        let chain_config = parse_chain_config(chain_config, env_config).await?;
        chain_hashmap.insert(chain_config.wormhole_chain_id, chain_config);
    }
    Ok(ChainData { chains: chain_hashmap })
}

pub async fn load_config(cli: WormholeOperator) -> Result<Config> {
    let mut env_config = match cli.command {
        WormholeOperatorCommand::Run {
            p2p_listen_address,
            bootstrap_nodes,
            idle_timeout_duration,
            event_subscription_mode,
            db_path,
            server_port,
        } => EnvConfig {
            p2p_listen_address,
            bootstrap_nodes,
            idle_timeout_duration,
            event_subscription_mode,
            db_path,
            server_port,
            bn254_keystore_method: cli.bn254_kms,
            bn254_key_path: cli.bn254_keystore_path,
            bn254_keystore_password: None,
            bn254_aws_access_key_id: cli.bn254_aws_access_key_id,
            bn254_aws_secret_access_key: cli.bn254_aws_secret_access_key,
            bn254_aws_default_region: cli.bn254_aws_default_region,
            bn254_aws_key_name: cli.bn254_aws_key_name,
            bn254_aws_password: cli.bn254_aws_password,
            eth_keystore_method: cli.eth_kms,
            eth_aws_access_key_id: cli.eth_aws_access_key_id,
            eth_aws_secret_access_key: cli.eth_aws_secret_access_key,
            eth_aws_region: cli.eth_aws_region,
            eth_aws_key_name: cli.eth_aws_key_name,
            eth_keypair_path: cli.eth_keystore_path,
            eth_private_key: cli.eth_private_key,
            eth_keystore_password: None,
        },
        _ => panic!("Code path is only for Run"),
    };
    let json_chain_config: JsonChainConfig =
        serde_json::from_str(&std::fs::read_to_string("config.json")?)?;
    let chain_config = get_chain_data(json_chain_config, &mut env_config).await?;

    Ok(Config { env_config, chain_config })
}

pub fn from_wormhole_format(wh_format_address: FixedBytes<32>) -> Result<Address> {
    let value: U256 = wh_format_address.into();
    if value >> 160 != Uint::ZERO {
        return Err(eyre::eyre!("Invalid Wormhole address format"));
    }

    Ok(Address::from(U160::from(value)))
}

pub fn to_wormhole_format(address: Address) -> FixedBytes<32> {
    let value_u160: U160 = address.0.into();
    let value_u256: U256 = U256::from(value_u160);
    FixedBytes::from(value_u256)
}
