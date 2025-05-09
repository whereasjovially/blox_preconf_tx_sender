use alloy::{
    consensus::Transaction,
    eips::eip2718::Encodable2718,
    hex,
    network::{EthereumWallet, TransactionBuilder},
    primitives::Address,
    providers::{fillers::FillProvider, ProviderBuilder, SendableTx},
    signers::local::PrivateKeySigner
};
use dotenv::dotenv;
use eyre::{bail, Context};
use reqwest::Url;
use tokio::time::sleep;
use utils::{available_next_proposer, send_rpc_request, create_tx_request};
use std::{env, str::FromStr, time::Duration};

mod types;
mod utils;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenv().ok();

    let _ = tracing_subscriber::fmt().with_target(false).try_init();
    let wallet = PrivateKeySigner::from_str(
        env::var("PRIVATEKEY")
            .expect("Invalid execution rpc in .env file")
            .as_str(),
    )?;
    let transaction_signer = EthereumWallet::from(wallet.clone());
    let el_url = env::var("EXECUTION_RPC").expect("Invalid execution rpc in .env file");
    let cl_url = env::var("CONSENSUS_RPC").expect("Invalid consensus rpc in .env file");
    let chain_id = env::var("CHAIN_ID").expect("Invalid consensus rpc in .env file").parse().expect("Invalid chainId format");
    let relay_url: Url = env::var("RELAY_RPC").expect("Invalid relay rpc in .env file").parse().expect("Invalid relay url");

    let sidecar_url: Url = env::var("SIDECAR_RPC")
        .expect("Invalid sidecar rpc in .env file")
        .parse()
        .expect("Invalid sidecar url");

    tracing::info!("Beacon: {}", cl_url);
    tracing::info!("RPC: {}", el_url);
    tracing::info!("Chain ID: {}", chain_id);
    tracing::info!("Relay URL: {}", relay_url);
    tracing::info!("Sidecar: {}", sidecar_url.as_str());
    tracing::info!("Sender Wallet: {}", wallet.address());


    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(transaction_signer)
        .on_http(el_url.parse().expect("Invalid rpc url"));

    let mut past_target_slots = Vec::new();

    loop{
        match send_preconf(&cl_url, &relay_url, &sidecar_url, &wallet, &provider, &past_target_slots, chain_id).await{
            Ok(slot) => {
                past_target_slots.push(slot);
            },
            Err(err) => {
                eprintln!("{}", err);
            }
        }
        sleep(Duration::from_secs(6)).await;
    }

 

    // let mut target_slot = 0;
    

    // match available_next_proposer(&cl_url.clone().parse().expect("Invaid beacon url"), &relay_url).await {
    //     Ok(slot) => {
    //         target_slot = slot;
    //     },
    //     Err(err) => {
    //         bail!("Not available proposers now");
    //     }
    // }

    // // println!("Testing tx requests...");
    // let _ = test_tx_requests(
    //     cl_url.clone(),
    //     1,
    //     target_slot,
    //     sidecar_url.clone(),
    //     wallet.clone(),
    //     provider.clone(),
    // )
    // .await;

    // println!("Testing blox tx requests...");
    // let _ = test_blox_tx_requests(
    //     cl_url.clone(),
    //     3,
    //     sidecar_url.clone(),
    //     wallet.clone(),
    //     provider.clone(),
    // )
    // .await;

    // println!("Testing blox&normal tx requests...");
    // let _ = test_blox_normal_tx_requests(
    //     cl_url.clone(),
    //     3,
    //     sidecar_url.clone(),
    //     wallet.clone(),
    //     provider.clone(),
    // )
    // .await;

    // println!("Testing limit exceeded tx count requests...");
    // let _ = test_tx_requests(
    //     cl_url.clone(),
    //     130,
    //     4,
    //     sidecar_url.clone(),
    //     wallet.clone(),
    //     provider.clone(),
    // )
    // .await;
    // println!("Sent 130 requests");

    // println!("Testing deadline expired...");
    // let _ = test_tx_requests_deadline_expired(
    //     cl_url.clone(),
    //     1,
    //     sidecar_url.clone(),
    //     wallet.clone(),
    //     provider.clone(),
    // )
    // .await;

    // println!("Testing passed slot...");
    // let _ = test_tx_requests_passed_slot(
    //     cl_url.clone(),
    //     1,
    //     sidecar_url.clone(),
    //     wallet.clone(),
    //     provider.clone(),
    // )
    // .await;

    // println!("Testing max commitment gas...");
    // let _ = test_tx_requests_max_commitment_gas(
    //     cl_url.clone(),
    //     5,
    //     sidecar_url.clone(),
    //     wallet.clone(),
    //     provider.clone(),
    // )
    // .await;

    // println!("Testing max transaction data size...");
    // let _ = test_tx_requests_max_tx_size(
    //     cl_url.clone(),
    //     1,
    //     sidecar_url.clone(),
    //     wallet.clone(),
    //     provider.clone(),
    // )
    // .await;

    // We can't set the max priorityfee over the max fee per gas.
    // println!("Testing max priority fee...");
    // let data = test_tx_requests_max_priority_fee(
    //     cl_url.clone(),
    //     5,
    //     sidecar_url.clone(),
    //     wallet.clone(),
    //     provider.clone(),
    // )
    // .await;
    // println!("Response: {:?}", data);

    // TODO: make it available to send large data to sidecar
    // println!("Testing limit exceeded data size...");
    // let _ = test_limt_exceeded_data_size(cl_url.clone(), 6, sidecar_url.clone(), wallet.clone(), provider.clone()).await;

    Ok(())
}

async fn send_preconf(
    cl_url: &String, 
    relay_url: &Url, 
    sidecar_url: &Url, 
    wallet: &PrivateKeySigner, 
    provider: &FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::fillers::JoinFill<
            alloy::providers::Identity,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        alloy::providers::fillers::WalletFiller<EthereumWallet>,
    >,
    alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
    alloy::transports::http::Http<reqwest::Client>,
    alloy::network::Ethereum,
>, passed_slots: &Vec<u64>, chain_id: u64) -> eyre::Result<u64>{
    loop{
        match available_next_proposer(&cl_url.clone().parse().expect("Invaid beacon url"), &relay_url).await {
            Ok(slot) => {
                if passed_slots.contains(&slot){
                    bail!("already sent tx request to slot {}.", slot);
                }
                match test_tx_requests(
                    1,
                    slot,
                    sidecar_url,
                    wallet,
                    provider,
                    chain_id
                )
                .await{
                    Ok(()) => {
                        println!("Sent preconf request to slot {}", slot);
                        return Ok(slot)
                    },
                    Err(err) => {
                        bail!("failed to send test tx request to slot {}. {}", slot, err);
                    }
                }
            },
            Err(err) => {
                eprintln!(
                    "No proposer yet ({}). Retrying in 6s…",
                    err
                );
                sleep(Duration::from_secs(6)).await;
            }
        }
    }
}

async fn test_tx_requests(
    tx_count: usize,
    target_slot: u64,
    sidecar_url: &Url,
    wallet: &PrivateKeySigner,
    provider: &FillProvider<
        alloy::providers::fillers::JoinFill<
            alloy::providers::fillers::JoinFill<
                alloy::providers::Identity,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::GasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::BlobGasFiller,
                        alloy::providers::fillers::JoinFill<
                            alloy::providers::fillers::NonceFiller,
                            alloy::providers::fillers::ChainIdFiller,
                        >,
                    >,
                >,
            >,
            alloy::providers::fillers::WalletFiller<EthereumWallet>,
        >,
        alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
        alloy::transports::http::Http<reqwest::Client>,
        alloy::network::Ethereum,
    >,
    chain_id: u64
) -> eyre::Result<()> {
    // Send the transactions to the devnet sidecar
    let mut next_nonce = None;

    let mut raw_txs = Vec::new();
    let mut tx_hashes = Vec::new();

    for _ in 0..tx_count {
        let mut req = create_tx_request(Address::from_str(
            "0xfCB6E353AD4F79245C7cB704ABCfFe2F48684241",
        )?);
        if let Some(next_nonce) = next_nonce {
            req.set_nonce(next_nonce);
        }
        let (raw_tx, tx_hash) = match provider
            .fill(req.clone())
            .await
            .wrap_err("failed to fill")?
        {
            SendableTx::Builder(_) => bail!("expected a raw transaction"),
            SendableTx::Envelope(raw) => {
                next_nonce = Some(raw.nonce() + 1);
                (raw.encoded_2718(), *raw.tx_hash())
            }
        };

        raw_txs.push(hex::encode(&raw_tx));
        tx_hashes.push(tx_hash);
    }

    send_rpc_request(
        raw_txs,
        tx_hashes,
        target_slot,
        sidecar_url.clone(),
        &wallet,
        chain_id
    )
    .await?;

    // Sleep for a bit to avoid spamming
    tokio::time::sleep(Duration::from_millis(200)).await;

    Ok(())
}

