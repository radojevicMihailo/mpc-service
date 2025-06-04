use std::error::Error;
use ark_bn254::{Fq12, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

pub(crate) fn compute_viewtag(data: &G1Affine, version: usize) -> Result<String, Box<dyn Error>>{
    match version{
        0 => {
            let x = data.x().ok_or("Point at infty")?.into_bigint().to_bytes_be()[0]; 
            Ok(hex::encode([x]))
        }
        1 => {
            let mut hasher = Sha256::new();
            let mut data_bytes = Vec::new();
            data.serialize_compressed(&mut data_bytes)?;
            hasher.update(&data_bytes); 
            let h: [u8; 32] = hasher.finalize().into();
            Ok(hex::encode([h[0]]))
        }
        _ => Err("Version must be either 0 or 1".into()),
    }    
}

pub(crate) fn get_first_coordinate(x: &Fq12) -> BigInt<4>{
    x.c0.c0.c0.into_bigint()
}

pub(crate) fn stealth_pub_key_to_address(stealth_pub_key:&PublicKey) -> String{
    // Takes last 20 bytes from the output of `Keccak256`
    let pub_bytes = stealth_pub_key.serialize_uncompressed();
    let hash = Keccak256::digest(&pub_bytes[1..]);
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(&hash[12..32]);
    let stealth_address = format!("0x{}", hex::encode(address_bytes)); 
    
    stealth_address
}


