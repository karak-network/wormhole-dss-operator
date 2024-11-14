use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::events::OperatorData;

pub async fn create_tables(connection: &Arc<Mutex<Connection>>) -> rusqlite::Result<()> {
    // Create payloads table with updated schema
    connection.lock().await.execute(
        r#"
            CREATE TABLE IF NOT EXISTS payloads (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                bls_public_key_g1   TEXT NOT NULL,
                bls_public_key_g2   TEXT NOT NULL,
                operator_address   TEXT NOT NULL,
                message_event      TEXT NOT NULL,
                unsigned_payload TEXT NOT NULL,
                signed_payload   TEXT NOT NULL,
                src_chain_id    INTEGER NOT NULL,
                dst_chain_id    INTEGER NOT NULL,
                ntt_manager_address TEXT NOT NULL,
                UNIQUE(unsigned_payload, bls_public_key_g2, src_chain_id, dst_chain_id, ntt_manager_address)
            );
            "#,
        (),
    )?;
    info!("Initialized database tables");
    Ok(())
}

pub async fn insert_payload(
    connection: &Arc<Mutex<Connection>>,
    operator_data: &OperatorData,
    ntt_manager_address: String,
) -> rusqlite::Result<()> {
    connection.lock().await.execute(
        r#"
        INSERT INTO payloads (
            bls_public_key_g1, 
            bls_public_key_g2, 
            operator_address, 
            message_event,
            unsigned_payload, 
            signed_payload,
            src_chain_id,
            dst_chain_id,
            ntt_manager_address
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
        (
            operator_data.bls_public_key_g1.to_string(),
            operator_data.bls_public_key_g2.to_string(),
            operator_data.operator_address.to_owned(),
            operator_data.message_event.to_owned(),
            operator_data.unsigned_payload.to_string(),
            operator_data.signed_payload.to_string(),
            operator_data.src_chain_id,
            operator_data.dst_chain_id,
            ntt_manager_address,
        ),
    )?;
    Ok(())
}
