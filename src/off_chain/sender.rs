use std::error::Error;
use ark_bn254::{Bn254, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger};
use secp256k1::{PublicKey, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};

use super::{common::{compute_viewtag, get_first_coordinate, stealth_pub_key_to_address}, utils::{deserialize_affine_point, deserialize_secp_pk, generate_bn254_key_pair, serialize_affine_point, serialize_field_element, serialize_secp_pk}};

pub fn send(request: &String) -> Result<String, Box<dyn Error>>{
    let request: SenderRequest = serde_json::from_str(&request)?;

    let viewing_pub_key = deserialize_affine_point(&request.viewing_pub_key)?; 
    let spending_pub_key = deserialize_secp_pk(&request.spending_pub_key)?;

    let (ephemeral_priv_key, ephemeral_pub_key) = calculate_ephemeral_key_pair();

    let (view_tag_data, ss) = compute_shared_secret(&ephemeral_priv_key, &viewing_pub_key); 
    let b = get_first_coordinate(&ss); 

    let stealth_pub_key = compute_stealth_pub_key(&spending_pub_key, &b)?;

    let stealth_address = stealth_pub_key_to_address(&stealth_pub_key);

    let view_tag = compute_viewtag(&view_tag_data, request.view_tag_version)?; 

    let response = SenderResponse{
        ephemeral_priv_key: serialize_field_element(&ephemeral_priv_key), 
        ephemeral_pub_key: serialize_affine_point(&ephemeral_pub_key)?,
        stealth_pub_key: serialize_secp_pk(&stealth_pub_key),  
        view_tag,
        stealth_address
    }; 
    let response = serde_json::to_string(&response)?; 

    Ok(response)
}

fn calculate_ephemeral_key_pair() -> (Fr, G1Affine){
   generate_bn254_key_pair()
}

fn compute_stealth_pub_key(x: &PublicKey, b: &BigInt<4>) -> Result<PublicKey, Box<dyn Error>>{
    let scalar_bytes: [u8; 32] = b.to_bytes_be().as_slice().try_into()?;
    let scalar = Scalar::from_be_bytes(scalar_bytes)?;
    let secp = Secp256k1::new();
    Ok(x.mul_tweak(&secp, &scalar)?)
}

fn compute_shared_secret(ephemeral_priv_key: &Fr, viewing_pub_key: &G1Affine) -> (G1Affine, Fq12){
    let r_times_v = ((*viewing_pub_key)*ephemeral_priv_key).into_affine(); 
    let g2 = G2Affine::generator(); 
    (r_times_v, Bn254::pairing(&r_times_v, &g2).0)
}

#[derive(Deserialize,Serialize)]
pub struct SenderResponse{
    pub ephemeral_priv_key: String, 
    pub ephemeral_pub_key: String, 
    pub view_tag: String, 
    pub stealth_pub_key: String, 
    pub stealth_address: String 
}

#[derive(Deserialize, Serialize)]
pub struct SenderRequest{
    pub viewing_pub_key: String, 
    pub spending_pub_key: String, 
    pub view_tag_version: usize
} 

#[cfg(test)]
mod sap_private_tests {
    use ark_bn254::g1::G1Affine;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_secret_share() {
        let mut rng = thread_rng(); 

        let viewing_sk = Fr::rand(&mut rng); 
        let g1 = G1Affine::generator(); 
        let viewing_pk = (g1*viewing_sk).into_affine(); 

        let (r, ephemeral_pk) = calculate_ephemeral_key_pair();

        let ss1 = compute_shared_secret(&r, &viewing_pk).1; 

        let product = (ephemeral_pk*viewing_sk).into_affine(); 
        let g2 = G2Affine::generator(); 
        let ss2 =  Bn254::pairing(&product, &g2).0; 

        assert!(ss1 == ss2);
    }
}
