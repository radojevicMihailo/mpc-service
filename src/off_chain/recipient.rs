use std::{error::Error, iter::zip};
use ark_bn254::{Bn254, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger};
use crypto_bigint::{NonZero, U256};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use crate::off_chain::{common::{compute_viewtag, get_first_coordinate, stealth_pub_key_to_address}, utils::{deserialize_affine_point, deserialize_field_element, deserialize_secret_key}};

pub fn scan(request: &String) -> Result<String, Box<dyn Error>>{
    let request: RecipientRequest = serde_json::from_str(&request)?; 

    assert!(request.viewtags.len() == request.ephemeral_pub_key_reg.len());

    let g2 = G2Affine::generator(); 

    let viewing_sk = deserialize_field_element(&request.viewing_sk)?; 
    let spending_sk = deserialize_secret_key(&request.spending_sk)?; 

    let mut stealth_addresses = Vec::new(); 
    let mut priv_keys = Vec::new(); 

    for (entry, viewtag) in zip(request.ephemeral_pub_key_reg, request.viewtags){       
        let ephemeral_pk = deserialize_affine_point(&entry)?;  

        let v_r_product = (ephemeral_pk * viewing_sk).into_affine(); 
        let computed_viewtag = compute_viewtag(&v_r_product, request.view_tag_version)?; 
  
        if *viewtag == computed_viewtag{      
            let ss =  Bn254::pairing(&v_r_product, &g2).0;
            let b = get_first_coordinate(&ss);

            let stealth_sk = compute_stealth_priv_key(&b, spending_sk)?; 
            let stealth_pk = compute_stealth_pub_key(&stealth_sk)?;

            let stealth_address = stealth_pub_key_to_address(&stealth_pk);

            stealth_addresses.push(stealth_address);
            priv_keys.push(hex::encode(stealth_sk.to_be_bytes()));
        }
    }

    let response = RecipientResponse{
        stealth_addresses, 
        priv_keys 
    }; 
    let response = serde_json::to_string(&response)?;

    Ok(response)
}


fn compute_stealth_pub_key(scalar: &U256) -> Result<PublicKey, Box<dyn Error>>{
    let sk_bytes: [u8; 32] = scalar.to_be_bytes();
    let sk = SecretKey::from_byte_array(&sk_bytes)?;
    let secp = Secp256k1::new();

    let stealth_pk = PublicKey::from_secret_key(&secp, &sk); 

    Ok(stealth_pk)
}

fn compute_stealth_priv_key(b: &BigInt<4>, k: SecretKey) -> Result<U256, Box<dyn Error>>{
    let k_bytes = k.secret_bytes(); 
    let k_u256 = U256::from_be_slice(&k_bytes); 
    
    let b_bytes = b.to_bytes_be();
    let b_u256 = U256::from_be_slice(&b_bytes); 

    let p = U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"); 

    let stealth_priv_key = b_u256.mul_mod(&k_u256,  &NonZero::new(p).unwrap());

    Ok(stealth_priv_key)
}

#[derive(Deserialize, Serialize)]
pub struct RecipientRequest{
    pub ephemeral_pub_key_reg: Vec<String>, 
    pub viewtags: Vec<String>, 
    pub view_tag_version: usize, 
    pub viewing_sk: String, 
    pub spending_sk: String, 
} 

#[derive(Serialize, Deserialize)]
pub struct RecipientResponse{
    pub priv_keys: Vec<String>, 
    pub stealth_addresses: Vec<String> 
} 
