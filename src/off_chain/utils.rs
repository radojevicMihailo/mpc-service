use std::error::Error;
use ark_bn254::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::thread_rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub fn serialize_affine_point(point: &G1Affine) -> Result<String, Box<dyn Error>>{
    let mut point_bytes = Vec::new(); 
    point.serialize_compressed(&mut point_bytes)?;
    
    Ok(hex::encode(point_bytes))
}

pub fn deserialize_affine_point(x: &String) -> Result<G1Affine, Box<dyn Error>>{
    let x = hex::decode(x)?;
    let point = G1Affine::deserialize_compressed(&*x)?; 
    Ok(point)
}

pub fn serialize_secp_pk(pk: &PublicKey) -> String{
    hex::encode(pk.serialize())
}

pub fn deserialize_secp_pk(x: &String) -> Result<PublicKey, Box<dyn Error>>{
    let x_bytes = hex::decode(x)?; 
    Ok(PublicKey::from_slice(&x_bytes)?)
}

pub fn serialize_field_element(x: &Fr) -> String{
    hex::encode(x.into_bigint().to_bytes_be())
}

pub fn deserialize_field_element(x: &String) -> Result<Fr, Box<dyn Error>>{
    let x_bytes = hex::decode(&x)?;
    Ok(Fr::from_be_bytes_mod_order(&x_bytes))
}

pub fn deserialize_secret_key(x: &String) ->Result<SecretKey, Box<dyn Error>>{
    let x_bytes = hex::decode(&x)?;
    assert!(x_bytes.len() == 32);
   
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&x_bytes); 

    let scalar = SecretKey::from_byte_array(&scalar_bytes)?;

    Ok(scalar)
}

pub fn serialize_secret_key(x: &SecretKey) -> String{
    let x_bytes = x.secret_bytes(); 
    hex::encode(&x_bytes)
}

pub fn generate_bn254_key_pair() -> (Fr, G1Affine) {
    let mut rng = ark_std::rand::thread_rng(); 
      
    let sk = Fr::rand(&mut rng);
    let pk = (G1Affine::generator()* sk).into_affine(); 

    (sk, pk)
}

pub fn generate_secp256k1_key_pair() -> (SecretKey, PublicKey){
   let mut rng = thread_rng();
   let secp = Secp256k1::new();
   
   let keypair =  secp256k1::Keypair::new(&secp, &mut rng); 
   
    (keypair.secret_key(), keypair.public_key())
}