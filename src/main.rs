use std::{str::FromStr, time::Duration};

use alloy::{
    consensus::{
        constants::GWEI_TO_WEI, BlobTransactionSidecar, SidecarBuilder, SimpleCoder, Transaction,
    },
    eips::eip2718::Encodable2718,
    hex,
    network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844},
    primitives::{keccak256, Address, B256, U256},
    providers::{ProviderBuilder, SendableTx},
    rpc::types::TransactionRequest,
    signers::{k256::SecretKey, local::PrivateKeySigner, Signer},
};
use eyre::{bail, Context, ContextCompat, Result};
use rand::Rng;
use reqwest::Url;
use serde_json::Value;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = tracing_subscriber::fmt().with_target(false).try_init();
    let wallet = PrivateKeySigner::from_str("5d2344259f42259f82d2c140aa66102ba89b57b4883ee441a8b312622bd42491")?;
    let transaction_signer = EthereumWallet::from(wallet.clone());
    let el_url = "http://162.55.190.235:32798";
    let cl_url = "http://162.55.190.235:32808";
    let sidecar_url: Url = "http://162.55.190.235:9061".parse().expect("Invalid sidecar url");

    let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(el_url.parse().expect("Invalid rpc url"));

    // Fetch the current slot from the devnet beacon node
    let slot = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();

    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    for _ in 0..1 {
        let mut req = create_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }

        let (raw_tx, tx_hash) = match provider.fill(req).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        send_rpc_request(
            vec![hex::encode(&raw_tx)],
            vec![tx_hash],
            slot + 8,
            sidecar_url.clone(),
            &wallet,
        )
        .await?;

        // Sleep for a bit to avoid spamming
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

fn create_tx_request(to: Address) -> TransactionRequest {
    let mut req = TransactionRequest::default();
    req = req.with_to(to).with_value(U256::from(100_000));
    req = req.with_input(rand::thread_rng().gen::<[u8; 32]>());

    let sidecar = SidecarBuilder::<SimpleCoder>::from_slice(b"Blobs are fun!");
    let sidecar: BlobTransactionSidecar = sidecar.build().unwrap();
    req = req.with_blob_sidecar(sidecar);
    req = req.with_max_fee_per_blob_gas(3_000_000);    

    req
}

async fn request_current_slot_number(beacon_url: &Url) -> Result<u64> {
    let res = reqwest::get(beacon_url.join("eth/v1/beacon/headers/head")?).await?;
    let res = res.json::<Value>().await?;
    let slot = res.pointer("/data/header/message/slot").wrap_err("missing slot")?;
    Ok(slot.as_u64().unwrap_or(slot.as_str().wrap_err("invalid slot type")?.parse()?))
}


async fn send_rpc_request(
    txs_rlp: Vec<String>,
    tx_hashes: Vec<B256>,
    target_slot: u64,
    target_sidecar_url: Url,
    wallet: &PrivateKeySigner,
) -> Result<()> {

    let signature = sign_request(tx_hashes.clone(), wallet).await?;

    let request = 
        serde_json::json!({
            "slot": target_slot,
            "txs": txs_rlp,
            "sender": wallet.address().to_string(),
            "signature": signature
        });
    

    tracing::info!(?tx_hashes, target_slot, %target_sidecar_url);

    let response = reqwest::Client::new()
        .post(target_sidecar_url.join("/api/v1/preconfirmation").unwrap())
        .header("content-type", "application/json")
        .body(serde_json::to_string(&request)?)
        .send()
        .await
        .wrap_err("failed to send POST request")?;

    let response = response.text().await?;

    // strip out long series of zeros in the response (to avoid spamming blob contents)
    let response = response.replace(&"0".repeat(32), ".").replace(&".".repeat(4), "");
    tracing::info!("Response: {:?}", response);
    Ok(())
}

async fn sign_request(
    tx_hashes: Vec<B256>,
    wallet: &PrivateKeySigner,
) -> eyre::Result<String> {
    let digest = {
        let mut data = Vec::new();
        let hashes = tx_hashes.iter().map(|hash| hash.as_slice()).collect::<Vec<_>>().concat();
        data.extend_from_slice(&hashes);
        keccak256(data)
    };

    let signature = hex::encode_prefixed(wallet.sign_hash(&digest).await?.as_bytes());

    Ok(signature)
}