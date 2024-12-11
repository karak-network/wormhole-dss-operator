use clap::{
    arg,
    builder::{styling::AnsiColor, Styles},
    command, Parser, Subcommand, ValueEnum,
};
use serde::Deserialize;

pub mod constants;
pub mod contracts;
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
pub enum Secp256k1Kms {
    Env,
    Local,
    Aws,
}

const CLAP_STYLING: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default())
    .usage(AnsiColor::Green.on_default())
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Green.on_default());

#[derive(Deserialize, Clone, Copy, Debug, ValueEnum, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EventSubscriptionMode {
    Latest,
    Safe,
    Finalized,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum WormholeOperatorCommand {
    Run {
        #[arg(short, long, env)]
        p2p_listen_address: String,

        #[arg(long, env)]
        bootstrap_nodes: String,

        #[arg(short, long, env)]
        idle_timeout_duration: u64,

        #[arg(short, long, default_value = "latest", env)]
        event_subscription_mode: EventSubscriptionMode,

        #[arg(short, long, env)]
        db_path: String,

        #[arg(short, long, env)]
        server_port: u16,

        #[arg(long, env)]
        prometheus_listen_address: Option<String>,

        #[arg(long, env)]
        p2p_private_key: Option<String>,
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
    pub bn254_keystore_path: Option<String>,

    #[arg(long, env, global = true)]
    pub bn254_keystore_password: Option<String>,

    #[arg(long, env, required_if_eq("bn254_kms", "aws"), global = true)]
    pub bn254_aws_access_key_id: Option<String>,

    #[arg(long, env, required_if_eq("bn254_kms", "aws"), global = true)]
    pub bn254_aws_secret_access_key: Option<String>,

    #[arg(long, env, required_if_eq("bn254_kms", "aws"), global = true)]
    pub bn254_aws_default_region: Option<String>,

    #[arg(long, env, required_if_eq("bn254_kms", "aws"), global = true)]
    pub bn254_aws_key_name: Option<String>,

    #[arg(long, env, global = true)]
    pub bn254_aws_password: Option<String>,

    #[arg(long, env, default_value = "local", global = true)]
    pub secp256k1_kms: Secp256k1Kms,

    #[arg(long, env, required_if_eq("secp256k1_kms", "env"), global = true)]
    pub secp256k1_private_key: Option<String>,

    #[arg(long, env, required_if_eq("secp256k1_kms", "local"), global = true)]
    pub secp256k1_keystore_path: Option<String>,

    #[arg(long, env, global = true)]
    pub secp256k1_keystore_password: Option<String>,

    #[arg(long, env, required_if_eq("secp256k1_kms", "aws"), global = true)]
    pub secp256k1_aws_access_key_id: Option<String>,

    #[arg(long, env, required_if_eq("secp256k1_kms", "aws"), global = true)]
    pub secp256k1_aws_secret_access_key: Option<String>,

    #[arg(long, env, required_if_eq("secp256k1_kms", "aws"), global = true)]
    pub secp256k1_aws_region: Option<String>,

    #[arg(long, env, required_if_eq("secp256k1_kms", "aws"), global = true)]
    pub secp256k1_aws_key_name: Option<String>,
}
