use std::sync::{Arc, Mutex};

use ark_bn254::{Bn254, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::BigInt;
use axum::{
    extract::Query, http::StatusCode, response::IntoResponse, Json
};
use cggmp21::keygen::NonThresholdMsg;
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{round_based, DataToSign, ExecutionId, PregeneratedPrimes};

use mpc_service::off_chain::common::{compute_viewtag, get_first_coordinate};
use mpc_service::off_chain::network::sink::OutgoingSink;
use mpc_service::off_chain::network::{setup::NetworkSetup, stream::IncomingStream};
use mpc_service::off_chain::protocol::MpcCurvy;
use mpc_service::off_chain::utils::{deserialize_affine_point, deserialize_field_element};
use rand_core::OsRng;
use sha2::Sha256;

use crate::{
    model::{KeyGenerationReqBody, SignTransactionReqBody},
    response::{KeyGenerationResponse, SignTransactionResponse},
};

use bincode;
use hex;

pub async fn health_checker_handler() -> impl IntoResponse {
    const MESSAGE: &str = "Build Simple CRUD API in Rust using Axum";

    let json_response = serde_json::json!({
        "status": "success",
        "message": MESSAGE
    });

    Json(json_response)
}

pub async fn key_generation_handler(
    opts: Option<Query<KeyGenerationReqBody>>
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let Query(opts) = opts.unwrap_or_default();

    let eid = ExecutionId::new(&opts.exec_id);

    let network_setup = NetworkSetup::setup_swarm(opts.local_party_id.unwrap(), opts.n.unwrap()).await.unwrap();
    let swarm = Arc::new(Mutex::new(network_setup.swarm));

    let incoming: IncomingStream<NonThresholdMsg<Secp256k1, SecurityLevel128, Sha256>> = IncomingStream::new(Arc::clone(&swarm), network_setup.my_topic.clone(), network_setup.broadcast_topic.clone());
    let outgoing: OutgoingSink<NonThresholdMsg<Secp256k1, SecurityLevel128, Sha256>> = OutgoingSink::new(Arc::clone(&swarm), network_setup.broadcast_topic.clone());

    let delivery = (incoming, outgoing); 
    let party = round_based::MpcParty::connected(delivery);

    println!("Generating key shares...");
    let incomplete_key_share = cggmp21::keygen::<Secp256k1>(eid, opts.local_party_id.unwrap(), opts.n.unwrap())
        .set_threshold(opts.t)
        .start(&mut OsRng, party)
        .await;

    println!("Key shares generated...");

    let serialized = bincode::serialize(&incomplete_key_share)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to serialize key share: {}", e)
        }))))?;
    let hex_encoded = hex::encode(serialized);

    let json_response = KeyGenerationResponse {
        incomplete_key_share: hex_encoded
    };

    Ok((StatusCode::OK, Json(json_response)))
}

pub async fn sign_transaction_handler(
    opts: Option<Query<SignTransactionReqBody>>
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let Query(opts) = opts.unwrap_or_default();

    let eid = ExecutionId::new(&opts.exec_id);

    let network_setup = NetworkSetup::setup_swarm(opts.local_party_id.unwrap(), opts.n.unwrap()).await.unwrap();
    let swarm = Arc::new(Mutex::new(network_setup.swarm));

    let incoming = IncomingStream::new(Arc::clone(&swarm), network_setup.my_topic.clone(), network_setup.broadcast_topic.clone());
    let outgoing = OutgoingSink::new(Arc::clone(&swarm), network_setup.broadcast_topic.clone());

    let delivery = (incoming, outgoing); 
    let party = round_based::MpcParty::connected(delivery);

    let pregenerated_primes: PregeneratedPrimes<SecurityLevel128> = cggmp21::PregeneratedPrimes::generate(&mut OsRng);

    println!("Generating aux info...");
    let aux_info = cggmp21::aux_info_gen(eid, opts.local_party_id.unwrap(), opts.n.unwrap(), pregenerated_primes)
        .start(&mut OsRng, party)
        .await;
    println!("Aux info generated...");

    let g2 = G2Affine::generator(); 

    let viewing_sk = deserialize_field_element(&opts.viewing_sk).unwrap();
    let ephemeral_pk = deserialize_affine_point(&opts.entry).unwrap();  

    let v_r_product = (ephemeral_pk * viewing_sk).into_affine(); 
    let computed_viewtag = compute_viewtag(&v_r_product, opts.view_tag_version).unwrap(); 

    let mut b: BigInt<4>;
    if *opts.viewtag == computed_viewtag{      
        let ss =  Bn254::pairing(&v_r_product, &g2).0;
        b = get_first_coordinate(&ss);
    }
    let key_share = MpcCurvy::update_shares_and_complete(opts.incomplete_key_share, b, aux_info.unwrap());

    let mut parties_indexes_at_keygen = vec!(); 
    for i in 0..opts.n.unwrap() {
        parties_indexes_at_keygen.push(i);
    }

    let data_to_sign: DataToSign<Secp256k1> = cggmp21::DataToSign::digest::<Sha256>(b"hello world"); 

    let incoming = IncomingStream::new(Arc::clone(&swarm), network_setup.my_topic.clone(), network_setup.broadcast_topic.clone());
    let outgoing = OutgoingSink::new(Arc::clone(&swarm), network_setup.broadcast_topic.clone());

    let delivery = (incoming, outgoing); 
    let party = round_based::MpcParty::connected(delivery);

    println!("Signing...");
    let signature = cggmp21::signing(eid, opts.local_party_id.unwrap(), &parties_indexes_at_keygen, &key_share)
        .sign(&mut OsRng, party, data_to_sign)
        .await;
    println!("Signed!");

    let serialized = bincode::serialize(&signature)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "Failed to serialize signature"
        }))))?;
    let hex_encoded = hex::encode(serialized);

    let json_response = SignTransactionResponse {
        signature: hex_encoded
    };

    Ok((StatusCode::OK, Json(json_response)))
}