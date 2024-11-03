use crate::{
    keypair::{
        g1_point_from_bytes_string, g2_point_from_bytes_string, G1PointAffine, G2PointAffine,
    },
    utils::Config,
};
use axum::{extract::State, Json};
use karak_rs::kms::keypair::bn254::algebra::{g1::G1Point, g2::G2Point};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub config: Arc<Mutex<Config>>,
}

#[derive(Deserialize)]
pub struct PayloadRequest {
    pub unsigned_payload: String,
}

#[derive(Serialize, Deserialize)]
pub struct OperatorData {
    pub bls_public_key_g1: G1PointAffine,
    pub bls_public_key_g2: G2PointAffine,
    pub operator_address: String,
    pub unsigned_payload: String,
    pub signature: G1PointAffine,
}

#[derive(Serialize, Deserialize)]
pub struct PayloadResponse {
    pub non_signing_operators: Vec<G1PointAffine>,
    pub aggregated_g1_key: G1PointAffine,
    pub aggregated_g2_key: G2PointAffine,
    pub aggregated_sign: G1PointAffine,
    pub unsigned_payload: String,
    pub operator_data: Vec<OperatorData>,
}

pub async fn query_payloads(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PayloadRequest>,
) -> Json<PayloadResponse> {
    let db = state.db.lock().await;

    let dst_chain_id = {
        let mut stmt = db
            .prepare("SELECT dst_chain_id FROM payloads WHERE message_event = ? LIMIT 1")
            .expect("Failed to prepare statement");
        stmt.query_row(params![payload.unsigned_payload], |row| row.get(0)).unwrap_or(0)
        // Default to 0 if not found
    };

    let signing_operator_data = {
        let mut stmt = db
            .prepare("SELECT bls_public_key_g1, bls_public_key_g2, operator_address, signed_payload, unsigned_payload FROM payloads WHERE message_event = ?")
            .expect("Failed to prepare statement");

        stmt.query_map(params![payload.unsigned_payload], |row| {
            Ok(OperatorData {
                bls_public_key_g1: <G1PointAffine>::from(g1_point_from_bytes_string(row.get(0)?)),
                bls_public_key_g2: <G2PointAffine>::from(g2_point_from_bytes_string(row.get(1)?)),
                operator_address: row.get(2)?,
                signature: <G1PointAffine>::from(g1_point_from_bytes_string(row.get(3)?)),
                unsigned_payload: row.get(4)?,
            })
        })
        .expect("Failed to execute query")
        .filter_map(Result::ok)
        .collect::<Vec<OperatorData>>()
    };

    drop(db); // Release the database lock before the next await

    let dst_chain_config =
        state.config.lock().await.chain_config.chains.get(&dst_chain_id).unwrap().clone();

    let all_operator_g1_keys =
        dst_chain_config.wormhole_dss_manager.get_all_operator_g1_keys().await.unwrap();
    let all_operator_g1_keys =
        all_operator_g1_keys.into_iter().map(|key| (key.X, key.Y)).collect::<Vec<G1PointAffine>>();

    let signing_operators = signing_operator_data
        .iter()
        .map(|payload| payload.bls_public_key_g1)
        .collect::<Vec<G1PointAffine>>();

    let non_signing_operators = all_operator_g1_keys
        .iter()
        .filter(|key| !signing_operators.contains(key))
        .cloned()
        .collect::<Vec<G1PointAffine>>();

    let aggregated_g1_key = signing_operator_data
        .iter()
        .map(|payload| G1Point::from(payload.bls_public_key_g1))
        .sum::<G1Point>();
    let aggregated_g2_key = signing_operator_data
        .iter()
        .map(|payload| G2Point::from(payload.bls_public_key_g2))
        .sum::<G2Point>();
    let aggregated_sign = signing_operator_data
        .iter()
        .map(|payload| G1Point::from(payload.signature))
        .sum::<G1Point>();

    let payload_response = PayloadResponse {
        non_signing_operators,
        aggregated_g1_key: <G1PointAffine>::from(aggregated_g1_key),
        aggregated_g2_key: <G2PointAffine>::from(aggregated_g2_key),
        aggregated_sign: <G1PointAffine>::from(aggregated_sign),
        unsigned_payload: payload.unsigned_payload,
        operator_data: signing_operator_data,
    };

    Json(payload_response)
}
