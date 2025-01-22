use std::{env, str::FromStr, time::Duration};
use dotenv::dotenv;
use alloy::{
    consensus::{
        constants::GWEI_TO_WEI, BlobTransactionSidecar, SidecarBuilder, SimpleCoder, Transaction,
    },
    eips::eip2718::Encodable2718,
    hex,
    network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844},
    primitives::{keccak256, Address, B256, U256},
    providers::{fillers::FillProvider, ProviderBuilder, SendableTx},
    rpc::types::TransactionRequest,
    signers::{k256::SecretKey, local::PrivateKeySigner, Signer},
};
use eyre::{bail, Context, ContextCompat, Result};
use rand::Rng;
use reqwest::Url;
use serde_json::Value;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv().ok();

    let _ = tracing_subscriber::fmt().with_target(false).try_init();
    let wallet = PrivateKeySigner::from_str(env::var("PRIVATEKEY").expect("Invalid execution rpc in .env file").as_str())?;
    let transaction_signer = EthereumWallet::from(wallet.clone());
    let el_url = env::var("EXECUTION_RPC").expect("Invalid execution rpc in .env file");
    let cl_url = env::var("CONSENSUS_RPC").expect("Invalid consensus rpc in .env file");
    let sidecar_url: Url = env::var("SIDECAR_RPC").expect("Invalid sidecar rpc in .env file").parse().expect("Invalid sidecar url");

    let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(transaction_signer)
            .on_http(el_url.parse().expect("Invalid rpc url"));

    // println!("Testing tx requests...");
    let _ = test_tx_requests(cl_url.clone(), 5, 4, sidecar_url.clone(), wallet.clone(), provider.clone()).await;

    // println!("Testing blox tx requests...");
    let _ = test_blox_tx_requests(cl_url.clone(), 3, sidecar_url.clone(), wallet.clone(), provider.clone()).await;

    // println!("Testing blox&normal tx requests...");
    let _ = test_blox_normal_tx_requests(cl_url.clone(), 3, sidecar_url.clone(), wallet.clone(), provider.clone()).await;

    // println!("Testing limit exceeded tx count requests...");
    let _ = test_tx_requests(cl_url.clone(), 130, 4, sidecar_url.clone(), wallet.clone(), provider.clone()).await;
    println!("Sent 130 requests");
    
    // println!("Testing deadline expired...");
    let _ = test_tx_requests_deadline_expired(cl_url.clone(), 1, sidecar_url.clone(), wallet.clone(), provider.clone()).await;

    // println!("Testing passed slot...");
    let _ = test_tx_requests_passed_slot(cl_url.clone(), 1, sidecar_url.clone(), wallet.clone(), provider.clone()).await;

    // println!("Testing max commitment gas...");
    let _ = test_tx_requests_max_commitment_gas(cl_url.clone(), 5, sidecar_url.clone(), wallet.clone(), provider.clone()).await;

    println!("Testing max transaction data size...");
    let _ = test_tx_requests_max_tx_size(cl_url.clone(), 1, sidecar_url.clone(), wallet.clone(), provider.clone()).await;

    // We can't set the max priorityfee over the max fee per gas.
    println!("Testing max priority fee...");
    let data = test_tx_requests_max_priority_fee(cl_url.clone(), 5, sidecar_url.clone(), wallet.clone(), provider.clone()).await;
    println!("Response: {:?}", data);

    // TODO: make it available to send large data to sidecar
    // println!("Testing limit exceeded data size...");
    // let _ = test_limt_exceeded_data_size(cl_url.clone(), 6, sidecar_url.clone(), wallet.clone(), provider.clone()).await;

    Ok(())
}

async fn test_blox_tx_requests(cl_url:String, tx_count:usize, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {

    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_blob_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }
    
    // Fetch the current slot from the devnet beacon node
    let slot: u64 = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot + 3,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}


async fn test_tx_requests_deadline_expired(cl_url:String, tx_count:usize, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {


    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }
    // Fetch the current slot from the devnet beacon node
    let slot = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot + 1,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}


async fn test_tx_requests_max_tx_size(cl_url:String, tx_count:usize, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {


    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_large_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }
    // Fetch the current slot from the devnet beacon node
    let slot = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot + 4,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}



async fn test_tx_requests_max_commitment_gas(cl_url:String, tx_count:usize, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {


    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_tx_request_with_gas_limit(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }
    // Fetch the current slot from the devnet beacon node
    let slot = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot + 4,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}


async fn test_tx_requests_max_priority_fee(cl_url:String, tx_count:usize, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {

    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_tx_request_with_priority(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => { 
                eyre::bail!("expected a raw transaction")
            },
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };
        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }
    // Fetch the current slot from the devnet beacon node
    let slot = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot + 4,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}


async fn test_tx_requests_passed_slot(cl_url:String, tx_count:usize, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {


    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }
    // Fetch the current slot from the devnet beacon node
    let slot = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot - 1,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}


async fn test_tx_requests(cl_url:String, tx_count:usize, far_target: u64, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {


    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }
    // Fetch the current slot from the devnet beacon node
    let slot = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot + far_target,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}


async fn test_blox_normal_tx_requests(cl_url:String, tx_count:usize, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {

    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_blob_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }

    for _ in 0..tx_count {
        let mut req = create_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }
    
    // Fetch the current slot from the devnet beacon node
    let slot: u64 = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot + 3,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}


async fn test_limt_exceeded_data_size(cl_url:String, tx_count:usize, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {
    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_blob_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);

        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }

    // Fetch the current slot from the devnet beacon node
    let slot: u64 = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot + 6,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}


async fn test_limt_exceeded_tx_count(cl_url:String, tx_count:usize, sidecar_url:Url, wallet:PrivateKeySigner, provider:FillProvider<alloy::providers::fillers::JoinFill<alloy::providers::fillers::JoinFill<alloy::providers::Identity, alloy::providers::fillers::JoinFill<alloy::providers::fillers::GasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::BlobGasFiller, alloy::providers::fillers::JoinFill<alloy::providers::fillers::NonceFiller, alloy::providers::fillers::ChainIdFiller>>>>, alloy::providers::fillers::WalletFiller<EthereumWallet>>, alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>, alloy::transports::http::Http<reqwest::Client>, alloy::network::Ethereum>) -> eyre::Result<()> {

    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;
    
    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_tx_request(Address::from_str("0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241")?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider.fill(req.clone()).await.wrap_err("failed to fill")? {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);

    }
    // Fetch the current slot from the devnet beacon node
    let slot: u64 = request_current_slot_number(&cl_url.parse().expect("Invalid beacon url")).await.unwrap();
    send_rpc_request(
        raw_txs,
        tx_hashes,
        slot + 3,
        sidecar_url.clone(),
        &wallet,
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
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

fn create_tx_request(to: Address) -> TransactionRequest {
    TransactionRequest::default()
    .with_to(to).with_value(U256::from(100_000))
    .with_input(rand::thread_rng().gen::<[u8; 32]>())
}


fn create_large_tx_request(to: Address) -> TransactionRequest {
    let data_size = 6 * 32 * 1024;
    let input_data: Vec<u8> = (0..data_size).map(|_| rand::thread_rng().gen::<u8>()).collect();

    TransactionRequest::default()
    .with_to(to).with_value(U256::from(100_000))
    .with_input(input_data)
}


fn create_tx_request_with_gas_limit(to: Address) -> TransactionRequest {
    TransactionRequest::default()
    .with_to(to).with_value(U256::from(100_000))
    .with_input(rand::thread_rng().gen::<[u8; 32]>())
    .with_gas_limit(3_000_000)
}


fn create_tx_request_with_priority(to: Address) -> TransactionRequest {
    TransactionRequest::default()
    .with_to(to).with_value(U256::from(100_000))
    .with_input(rand::thread_rng().gen::<[u8; 32]>())
    .with_max_fee_per_gas(200_000_000_000)
    .with_max_priority_fee_per_gas(200_000_000_001)    
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
    

    tracing::info!("tx number: {}, target slot: {}, sidecar: {}", tx_hashes.len(), target_slot, target_sidecar_url);

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