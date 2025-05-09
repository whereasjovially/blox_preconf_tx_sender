
use alloy::{
    hex,
    primitives::{keccak256, B256},
    signers::{local::PrivateKeySigner, Signer},
};

use eyre::{bail, Context, ContextCompat, Result};
use reqwest::{StatusCode, Url};
use serde_json::Value;
use crate::types::Validator;

use alloy::{
    consensus::{
        BlobTransactionSidecar, SidecarBuilder, SimpleCoder,
    },
    network::{TransactionBuilder, TransactionBuilder4844},
    primitives::{Address, U256},
    rpc::types::TransactionRequest,
};
use rand::Rng;



pub async fn request_current_slot_number(beacon_url: &Url) -> Result<u64> {
    let res = reqwest::get(beacon_url.join("eth/v1/beacon/headers/head")?).await?;
    let res = res.json::<Value>().await?;
    let slot = res
        .pointer("/data/header/message/slot")
        .wrap_err("missing slot")?;
    Ok(slot
        .as_u64()
        .unwrap_or(slot.as_str().wrap_err("invalid slot type")?.parse()?))
}

pub async fn available_next_proposer(beacon_url: &Url, relay_url: &Url) -> Result<u64> {

    match request_current_slot_number(beacon_url).await {
        Ok(cur_slot) => {
            let next_epoch_start_slot = (cur_slot / 32 + 1) * 32;
            let res = reqwest::get(relay_url.join("relay/v1/builder/validators")?).await?;
            let text = res.text().await?;

            let validators: Vec<Validator> = serde_json::from_str(&text)
            .context("failed to parse validators JSON")?;
            
            for v in validators {
                if v.slot > cur_slot + 3 && v.slot < next_epoch_start_slot {
                    return Ok(v.slot);
                }
            }

            bail!("Not available proposer");
       }, 
        Err(err) => {
            return Err(err)
        }
    }
   
}

pub async fn send_rpc_request(
    txs_rlp: Vec<String>,
    tx_hashes: Vec<B256>,
    target_slot: u64,
    target_sidecar_url: Url,
    wallet: &PrivateKeySigner,
    chain_id: u64
) -> Result<()> {
    let signature = sign_request(tx_hashes.clone(), wallet, target_slot).await?;

    let request = serde_json::json!({
        "slot": target_slot,
        "txs": txs_rlp,
        "sender": wallet.address().to_string(),
        "signature": signature,
        "chain_id": chain_id
    });

    tracing::info!(
        "tx number: {}, target slot: {}, sidecar: {}",
        tx_hashes.len(),
        target_slot,
        target_sidecar_url
    );

    let response = reqwest::Client::new()
        .post(target_sidecar_url.join("/api/v1/preconfirmation").unwrap())
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request)?)
        .send()
        .await
        .wrap_err("failed to send POST request")?;


    if response.status() != StatusCode::OK {
        let text = response.text().await?;
        // let error = response.json::<ErrorResponse>().await?;
        bail!(text);
    }

    Ok(())
}

async fn sign_request(tx_hashes: Vec<B256>, wallet: &PrivateKeySigner, slot: u64) -> eyre::Result<String> {
    let digest = {
        let mut data = Vec::new();
        
        data.extend_from_slice(&slot.to_be_bytes());

        let hashes = tx_hashes
            .iter()
            .map(|hash| hash.as_slice())
            .collect::<Vec<_>>()
            .concat();
        data.extend_from_slice(&hashes);
        keccak256(data)
    };

    let signature = hex::encode_prefixed(wallet.sign_hash(&digest).await?.as_bytes());

    Ok(signature)
}


fn create_blob_tx_request(to: Address) -> TransactionRequest {
    let mut req = TransactionRequest::default();
    req = req.with_to(to).with_value(U256::from(100_000));
    req = req.with_input(rand::thread_rng().gen::<[u8; 32]>());

    let sidecar = SidecarBuilder::<SimpleCoder>::from_slice(b"Blobs are fun!");
    let sidecar: BlobTransactionSidecar = sidecar.build().unwrap();
    req = req.with_blob_sidecar(sidecar);
    req = req.with_max_fee_per_blob_gas(3_000_000);

    req
}

pub fn create_tx_request(to: Address) -> TransactionRequest {
    TransactionRequest::default()
        .with_to(to)
        .with_value(U256::from(100_000))
        .with_input(rand::thread_rng().gen::<[u8; 32]>())
}

fn create_large_tx_request(to: Address) -> TransactionRequest {
    let data_size = 6 * 32 * 1024;
    let input_data: Vec<u8> = (0..data_size)
        .map(|_| rand::thread_rng().gen::<u8>())
        .collect();

    TransactionRequest::default()
        .with_to(to)
        .with_value(U256::from(100_000))
        .with_input(input_data)
}

fn create_tx_request_with_gas_limit(to: Address) -> TransactionRequest {
    TransactionRequest::default()
        .with_to(to)
        .with_value(U256::from(100_000))
        .with_input(rand::thread_rng().gen::<[u8; 32]>())
        .with_gas_limit(3_000_000)
}

fn create_tx_request_with_priority(to: Address) -> TransactionRequest {
    TransactionRequest::default()
        .with_to(to)
        .with_value(U256::from(100_000))
        .with_input(rand::thread_rng().gen::<[u8; 32]>())
        .with_max_fee_per_gas(200_000_000_000)
        .with_max_priority_fee_per_gas(200_000_000_001)
}
