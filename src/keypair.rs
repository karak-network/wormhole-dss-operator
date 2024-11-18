use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, Keccak256, Signature as EcdsaSignature, U256},
    providers::{ProviderBuilder, WsConnect},
    signers::{
        aws::AwsSigner,
        local::{LocalSigner, PrivateKeySigner},
        Signer as EdsaSigner,
    },
    transports::http::reqwest::Url,
};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::config::{Credentials, SharedCredentialsProvider};
use eyre::{Context, Result};
use karak_rs::kms::{
    keypair::{
        bn254::{
            self,
            algebra::{g1::G1Point, g2::G2Point},
            bls::signature::Signature,
            G1Pubkey, G2Pubkey, PublicKey,
        },
        Signer, Verifier,
    },
    keystore::{
        self,
        aws::AwsKeystoreParams,
        traits::{AsyncEncryptedKeystore, EncryptedKeystore},
    },
};
use std::{path::PathBuf, str::FromStr};

use crate::{contracts::RecommendedWalletProvider, Bn254Kms, EthKms};

pub type G1PointAffine = (U256, U256);
pub type G2PointAffine = ([U256; 2], [U256; 2]);

pub enum KeystoreType {
    Local {
        keystore_path: String,
        password: String,
    },
    Aws {
        region: String,
        access_key_id: String,
        secret_access_key: String,
        key_name: String,
        password: String,
    },
}

pub enum EthKeystoreType {
    Env {
        eth_private_key: String,
    },
    Local {
        eth_keystore_path: String,
        eth_keystore_password: String,
    },
    Aws {
        eth_access_key_id: String,
        eth_aws_secret_access_key: String,
        eth_aws_region: String,
        eth_aws_key_name: String,
    },
}

#[allow(clippy::too_many_arguments)]
pub async fn prompt_load_keypair(
    bn254_keystore_method: Bn254Kms,
    bn254_key_path: Option<String>,
    bn254_keystore_password: Option<String>,
    aws_access_key_id: Option<String>,
    aws_secret_access_key: Option<String>,
    aws_region: Option<String>,
    aws_key_name: Option<String>,
    aws_password: Option<String>,
) -> eyre::Result<bn254::Keypair> {
    let keypair = load_keypair_from_config(
        bn254_keystore_method,
        bn254_key_path,
        bn254_keystore_password,
        aws_access_key_id,
        aws_secret_access_key,
        aws_region,
        aws_key_name,
        aws_password,
    )
    .await?;

    Ok(keypair)
}

async fn load_keypair(keystore_type: KeystoreType) -> Result<bn254::Keypair, eyre::Error> {
    let keypair: bn254::Keypair = match keystore_type {
        KeystoreType::Local { keystore_path, password } => {
            let local_keystore =
                keystore::local::LocalEncryptedKeystore::new(PathBuf::from(keystore_path));
            local_keystore.retrieve(&password)?
        }
        KeystoreType::Aws { region, access_key_id, secret_access_key, key_name, password } => {
            let credentials = Credentials::new(access_key_id, secret_access_key, None, None, "");
            let aws_config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region))
                .credentials_provider(SharedCredentialsProvider::new(credentials))
                .load()
                .await;
            let aws_keystore = keystore::aws::AwsEncryptedKeystore::new(&aws_config);
            aws_keystore
                .retrieve(password.as_str(), &AwsKeystoreParams { secret_name: key_name })
                .await?
        }
    };
    Ok(keypair)
}

#[allow(clippy::too_many_arguments)]
async fn load_keypair_from_config(
    bn254_keystore_method: Bn254Kms,
    bn254_key_path: Option<String>,
    bn254_keystore_password: Option<String>,
    aws_access_key_id: Option<String>,
    aws_secret_access_key: Option<String>,
    aws_region: Option<String>,
    aws_key_name: Option<String>,
    aws_password: Option<String>,
) -> Result<bn254::Keypair, eyre::Error> {
    let keystore_type = match bn254_keystore_method {
        Bn254Kms::Local => {
            if bn254_key_path.is_none() {
                return Err(eyre::eyre!("KEY_PATH env variable must be set for LOCAL keystore"));
            }
            KeystoreType::Local {
                keystore_path: bn254_key_path.expect("keystore path is NONE"),
                password: bn254_keystore_password.expect("keystore password is NONE"),
            }
        }
        Bn254Kms::Aws => {
            if aws_access_key_id.is_none() {
                return Err(eyre::eyre!("AWS_KEY_NAME env variable must be set for AWS keystore"));
            }
            KeystoreType::Aws {
                access_key_id: aws_access_key_id.expect("aws access key id is NONE"),
                secret_access_key: aws_secret_access_key.expect("aws secret access key is NONE"),
                region: aws_region.expect("aws region is NONE"),
                key_name: aws_key_name.expect("aws key name is NONE"),
                password: aws_password.expect("aws password is NONE"),
            }
        }
    };
    load_keypair(keystore_type).await
}

pub fn sign(payload: &Bytes, keypair: &bn254::Keypair) -> eyre::Result<Bytes> {
    // We Keccak256 hash the message to a 32 bytes hash

    let mut hasher = Keccak256::new();
    hasher.update(payload);
    let result = hasher.finalize();
    let mut hash_buffer = [0u8; 32];
    hash_buffer.copy_from_slice(result.as_ref());

    let signature = keypair.sign(&hash_buffer);
    Ok(signature.to_bytes().unwrap().into())
}

pub fn sign_hash(payload: Bytes, keypair: bn254::Keypair) -> G1Point {
    // We Keccak256 hash the message to a 32 bytes hash

    let mut hash_buffer = [0u8; 32];
    hash_buffer.copy_from_slice(payload.as_ref());

    keypair.sign(&hash_buffer)
}

pub fn verify(signature: Bytes, payload: Bytes, public_key: Bytes) -> bool {
    let pubkey_g2 = G2Pubkey::from_bytes(&public_key).expect("Invalid public key");
    let signature_g1 = Signature::from_bytes(signature.as_ref()).expect("Invalid signature");

    let mut hasher = Keccak256::new();
    hasher.update(payload);
    let result = hasher.finalize();
    let mut hash_buffer = [0u8; 32];
    hash_buffer.copy_from_slice(result.as_ref());

    pubkey_g2.verify(&hash_buffer, &signature_g1).is_ok()
}

pub fn verify_bls_keys(
    public_key_g1: Bytes,
    public_key_g2: Bytes,
    signature: Bytes,
    payload: Bytes,
) -> bool {
    let pubkey_g2 = G2Pubkey::from_bytes(&public_key_g2).expect("Invalid public key");
    let pubkey_g1 = G1Pubkey::from_bytes(&public_key_g1).expect("Invalid public key");
    let public_key = PublicKey { g1: pubkey_g1, g2: pubkey_g2 };
    let signature = Signature::from_bytes(&signature).expect("Invalid signature");

    let mut hasher = Keccak256::new();
    hasher.update(payload);
    let result = hasher.finalize();
    let mut hash_buffer = [0u8; 32];
    hash_buffer.copy_from_slice(result.as_ref());

    public_key.verify(&hash_buffer, &signature).is_ok()
}

#[allow(clippy::too_many_arguments)]
pub async fn get_operator_signed_message(
    message: &str,
    eth_key_method: EthKms,
    eth_private_key: Option<String>,
    eth_keystore_path: Option<String>,
    eth_keystore_password: Option<String>,
    eth_aws_access_key_id: Option<String>,
    eth_aws_secret_access_key: Option<String>,
    eth_aws_region: Option<String>,
    eth_aws_key_name: Option<String>,
) -> eyre::Result<(Address, EcdsaSignature)> {
    let eth_keystore = load_eth_keystore(
        eth_key_method,
        eth_private_key,
        eth_keystore_path,
        eth_keystore_password,
        eth_aws_access_key_id,
        eth_aws_secret_access_key,
        eth_aws_region,
        eth_aws_key_name,
    )
    .await?;

    match eth_keystore {
        EthKeystoreType::Env { eth_private_key } => {
            let signer = PrivateKeySigner::from_str(eth_private_key.as_str())?;
            Ok((signer.address(), signer.sign_message(message.as_bytes()).await?))
        }
        EthKeystoreType::Local { eth_keystore_path, eth_keystore_password } => {
            let keystore_file_path = PathBuf::from(eth_keystore_path);
            let signer = LocalSigner::decrypt_keystore(keystore_file_path, eth_keystore_password)?;
            Ok((signer.address(), signer.sign_message(message.as_bytes()).await?))
        }
        EthKeystoreType::Aws {
            eth_access_key_id,
            eth_aws_secret_access_key,
            eth_aws_region,
            eth_aws_key_name,
        } => {
            let credentials =
                Credentials::new(eth_access_key_id, eth_aws_secret_access_key, None, None, "");
            let aws_config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(eth_aws_region))
                .credentials_provider(SharedCredentialsProvider::new(credentials))
                .load()
                .await;
            let client = aws_sdk_kms::Client::new(&aws_config);
            let signer = AwsSigner::new(client, eth_aws_key_name, Some(1)).await?;
            Ok((signer.address(), signer.sign_message(message.as_bytes()).await?))
        }
    }
}

pub fn g1_point_from_bytes_string(s: String) -> eyre::Result<G1Point> {
    Ok(G1Point::from_bytes(Bytes::from_str(s.as_str())?)?)
}

pub fn g2_point_from_bytes_string(s: String) -> eyre::Result<G2Point> {
    Ok(G2Point::from_bytes(Bytes::from_str(s.as_str())?)?)
}

#[allow(clippy::too_many_arguments)]
pub async fn get_wallet_provider(
    eth_key_method: EthKms,
    eth_private_key: Option<String>,
    eth_keystore_path: Option<String>,
    eth_keystore_password: Option<String>,
    eth_aws_access_key_id: Option<String>,
    eth_aws_secret_access_key: Option<String>,
    eth_aws_region: Option<String>,
    eth_aws_key_name: Option<String>,
    ws_rpc_url: String,
) -> Result<RecommendedWalletProvider> {
    let eth_keystore = load_eth_keystore(
        eth_key_method,
        eth_private_key,
        eth_keystore_path,
        eth_keystore_password,
        eth_aws_access_key_id,
        eth_aws_secret_access_key,
        eth_aws_region,
        eth_aws_key_name,
    )
    .await?;
    match eth_keystore {
        EthKeystoreType::Env { eth_private_key } => {
            let signer = PrivateKeySigner::from_str(eth_private_key.as_str())?;
            let wallet = EthereumWallet::from(signer);
            Ok(ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(wallet)
                .on_ws(WsConnect::new(ws_rpc_url))
                .await
                .wrap_err("Failed to initialize WebSocket provider")?)
        }
        EthKeystoreType::Local { eth_keystore_path, eth_keystore_password } => {
            let keystore_file_path = PathBuf::from(eth_keystore_path);
            let signer = LocalSigner::decrypt_keystore(keystore_file_path, eth_keystore_password)?;
            let wallet = EthereumWallet::from(signer);
            Ok(ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(wallet)
                .on_ws(WsConnect::new(ws_rpc_url.parse::<Url>()?))
                .await
                .wrap_err("Failed to initialize WebSocket provider")?)
        }
        EthKeystoreType::Aws {
            eth_access_key_id,
            eth_aws_secret_access_key,
            eth_aws_region,
            eth_aws_key_name,
        } => {
            let credentials =
                Credentials::new(eth_access_key_id, eth_aws_secret_access_key, None, None, "");
            let aws_config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(eth_aws_region))
                .credentials_provider(SharedCredentialsProvider::new(credentials))
                .load()
                .await;
            let client = aws_sdk_kms::Client::new(&aws_config);
            let signer = AwsSigner::new(client, eth_aws_key_name, Some(1)).await?;
            let wallet = EthereumWallet::from(signer);
            Ok(ProviderBuilder::new()
                .with_recommended_fillers()
                .wallet(wallet)
                .on_ws(WsConnect::new(ws_rpc_url.parse::<Url>()?))
                .await
                .wrap_err("Failed to initialize WebSocket provider")?)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn load_eth_keystore(
    eth_key_method: EthKms,
    eth_private_key: Option<String>,
    eth_keystore_path: Option<String>,
    eth_keystore_password: Option<String>,
    eth_aws_key_id: Option<String>,
    eth_aws_secret_access_key: Option<String>,
    eth_aws_region: Option<String>,
    eth_aws_key_name: Option<String>,
) -> Result<EthKeystoreType> {
    let keystore_type = match eth_key_method {
        EthKms::Env => EthKeystoreType::Env {
            eth_private_key: eth_private_key.expect("eth private key is NONE"),
        },
        EthKms::Local => EthKeystoreType::Local {
            eth_keystore_path: eth_keystore_path.expect("keystore path is NONE"),
            eth_keystore_password: eth_keystore_password.expect("keystore password is NONE"),
        },
        EthKms::Aws => EthKeystoreType::Aws {
            eth_access_key_id: eth_aws_key_id.expect("aws access key id is NONE"),
            eth_aws_secret_access_key: eth_aws_secret_access_key
                .expect("aws secret access key is NONE"),
            eth_aws_region: eth_aws_region.expect("aws region is NONE"),
            eth_aws_key_name: eth_aws_key_name.expect("aws key name is NONE"),
        },
    };
    Ok(keystore_type)
}
