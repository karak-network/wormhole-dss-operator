use clap::{
    arg,
    builder::{styling::AnsiColor, Styles},
    command, Parser, Subcommand, ValueEnum,
};
use serde::Deserialize;

pub mod constants;
pub mod contracts;
pub mod error;
pub mod events;
pub mod keypair;
pub mod p2p;
pub mod register;
pub mod server;
pub mod table;
pub mod utils;

#[derive(Deserialize, Clone, Copy, Debug, ValueEnum, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Bn254Kms {
    Local,
    Aws,
}

#[derive(Deserialize, Clone, Copy, Debug, ValueEnum, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EthKms {
    Env,
    Local,
    Aws,
}

const CLAP_STYLING: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default())
    .usage(AnsiColor::Green.on_default())
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Green.on_default());

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum WormholeOperatorCommand {
    Run {
        #[arg(short, long, env)]
        p2p_listen_address: String,

        #[arg(long, env)]
        bootstrap_nodes: String,

        #[arg(long, env)]
        idle_timeout_duration: u64,

        #[arg(long, env)]
        event_subscription_mode: String,

        #[arg(long, env)]
        db_path: String,

        #[arg(long, env)]
        server_port: u16,
    },

    Register,
}

#[derive(Parser)]
#[command(version, about, long_about, styles = CLAP_STYLING)]
pub struct WormholeOperator {
    #[command(subcommand)]
    pub command: WormholeOperatorCommand,

    #[arg(short, long, env, default_value = "local", global = true)]
    pub bn254_kms: Bn254Kms,

    #[arg(long, env, required_if_eq("bn254_kms", "local"), global = true)]
    pub bn254_key_path: Option<String>,

    #[arg(long, env, required_if_eq("bn254_kms", "aws"), global = true)]
    pub bn254_aws_access_key_id: Option<String>,

    #[arg(long, env, required_if_eq("bn254_kms", "aws"), global = true)]
    pub bn254_aws_secret_access_key: Option<String>,

    #[arg(long, env, required_if_eq("bn254_kms", "aws"), global = true)]
    pub bn254_aws_default_region: Option<String>,

    #[arg(long, env, required_if_eq("bn254_kms", "aws"), global = true)]
    pub bn254_aws_key_name: Option<String>,

    #[arg(long, env, required_if_eq("bn254_kms", "aws"), global = true)]
    pub bn254_aws_password: Option<String>,

    #[arg(long, env, default_value = "env", global = true)]
    pub eth_kms: EthKms,

    #[arg(long, env, required_if_eq("eth_kms", "env"), global = true)]
    pub eth_private_key: Option<String>,

    #[arg(long, env, required_if_eq("eth_kms", "local"), global = true)]
    pub eth_keystore_path: Option<String>,

    #[arg(long, env, required_if_eq("eth_kms", "aws"), global = true)]
    pub eth_aws_access_key_id: Option<String>,

    #[arg(long, env, required_if_eq("eth_kms", "aws"), global = true)]
    pub eth_aws_secret_access_key: Option<String>,

    #[arg(long, env, required_if_eq("eth_kms", "aws"), global = true)]
    pub eth_aws_region: Option<String>,

    #[arg(long, env, required_if_eq("eth_kms", "aws"), global = true)]
    pub eth_aws_key_name: Option<String>,
}
