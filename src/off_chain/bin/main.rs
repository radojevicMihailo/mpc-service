use tracing_subscriber::EnvFilter;
use std::{env, error::Error};
use mpc_service::off_chain::protocol::MpcCurvy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>>{
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let args: Vec<String> = env::args().collect();
    let local_party_id = u16::from_str_radix(&args[1], 10).unwrap();

    let n = 2;

    let protocol = MpcCurvy::new(local_party_id, n).await?; 

    protocol.run().await?;

    Ok(())
}