use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::Address,
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Identity, RootProvider,
    },
    pubsub::PubSubFrontend,
    sol,
};
use thiserror::Error;
use WormholeDSS::WormholeDSSInstance;
use BN254::G1Point;

use crate::keypair::G1PointAffine;

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    Wormhole,
    "abi/wormhole.json"
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    WormholeDSS,
    "abi/wormholeDSS.json"
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    Vault,
    "abi/Vault.json"
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[allow(missing_docs)]
    #[sol(rpc)]
    ERC20Mintable,
    "abi/ERC20Mintable.json"
);

#[derive(Debug, Error)]
pub enum TaskError {
    #[error("Contract call error")]
    ContractCallError,

    #[error("Failed to submit task error: {0}")]
    SubmitTaskError(String),

    #[error("Operator not found")]
    OperatorNotFound,

    #[error("Majority not reached")]
    MajorityNotReached,

    #[error("JSON parsing error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Failed to load contract JSON: {0}")]
    LoadContractJsonError(String),

    #[error("Custom URL error: {0}")]
    CustomUrlError(String),
}

pub type RecommendedWalletProvider = FillProvider<
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
>;

#[derive(Clone, Debug)]
pub struct ContractManager {
    pub wormhole_dss_instance:
        WormholeDSS::WormholeDSSInstance<PubSubFrontend, RecommendedWalletProvider>,
}

impl ContractManager {
    pub async fn new(
        wormhole_dss_address: Address,
        ws_rpc: RecommendedWalletProvider,
    ) -> Result<Self, TaskError> {
        let wormhole_dss_instance = WormholeDSSInstance::new(wormhole_dss_address, ws_rpc);

        Ok(Self { wormhole_dss_instance })
    }

    pub async fn is_operator_registered(
        &self,
        operator_address: String,
    ) -> Result<bool, TaskError> {
        Ok(self
            .wormhole_dss_instance
            .isOperatorRegistered(operator_address.parse::<Address>().unwrap())
            .call()
            .await
            .map_err(|_| TaskError::OperatorNotFound)
            .unwrap()
            ._0)
    }

    pub async fn get_all_operator_g1_keys(&self) -> Result<Vec<G1Point>, TaskError> {
        let all_operators_g1_key =
            self.wormhole_dss_instance.allOperatorsG1().call().await.unwrap()._0;
        Ok(all_operators_g1_key)
    }

    pub async fn operator_address_matches_g1_key(
        &self,
        operator_address: String,
        g1_key: G1PointAffine,
    ) -> Result<bool, TaskError> {
        let operator_g1_key = self
            .wormhole_dss_instance
            .operatorG1(operator_address.parse::<Address>().unwrap())
            .call()
            .await
            .map_err(|_| TaskError::ContractCallError)
            .unwrap()
            ._0;
        Ok((g1_key.0, g1_key.1) == (operator_g1_key.X, operator_g1_key.Y))
    }
}
