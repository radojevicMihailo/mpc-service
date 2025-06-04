use std::{collections::HashMap, str::FromStr, sync::{Arc, Mutex}};

use cggmp21::{keygen::NonThresholdMsg, round_based::{self}, security_level::SecurityLevel128, supported_curves::Secp256k1, DataToSign, ExecutionId, PregeneratedPrimes};
use futures::StreamExt;
use libp2p::{gossipsub, swarm::SwarmEvent};
use rand::RngCore;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::error::Error;

use crate::off_chain::network::{sink::OutgoingSink, stream::IncomingStream};

use super::network::{behaviour::MyBehaviourEvent, hash_map::{PARTY_TO_PEER_MAP, PEER_TO_PARTY_MAP}, setup::NetworkSetup};
use ark_ff::{BigInt, BigInteger};
use cggmp21::{generic_ec::{curves::secp256k1::SecretScalar, NonZero, Scalar}, key_share::{DirtyAuxInfo, Valid, Validate}, IncompleteKeyShare, KeyShare};
pub struct MpcCurvy{
    network_setup: NetworkSetup,
    n: u16,
    local_party_id: u16,
}

impl MpcCurvy{
    async fn gen_exec_id(&mut self) -> Vec<u8>{
        let mut rand_bytes = [0u8; 16]; 
        OsRng.fill_bytes(&mut rand_bytes);
        let my_nonce = rand_bytes.to_vec();
        self.network_setup.swarm.behaviour_mut().gossipsub.publish(self.network_setup.broadcast_topic.clone(), my_nonce.clone()).unwrap();
    
        let mut seen: HashMap<String, Vec<u8>> = HashMap::new();
        seen.insert(PARTY_TO_PEER_MAP.get(&self.local_party_id).unwrap().to_string(), my_nonce);
    
        while seen.len() < self.n as usize{
            match self.network_setup.swarm.select_next_some().await{
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message_id: _, message })) =>{
                    if message.topic == self.network_setup.broadcast_topic.clone().hash() && message.data.len() == 16 {
                        let peer_id = propagation_source.to_string();
                        if PEER_TO_PARTY_MAP.contains_key(&peer_id) {
                            seen.insert(peer_id.clone(), message.data);
                        }
                    }
                }
                _ => {}
            }
        }
    
        let mut entries: Vec<_> = seen.into_iter().collect();
        entries.sort_by_key(|(peer, _nonce)| peer.to_string());
    
        let concatenated: Vec<u8> = entries
            .into_iter()
            .flat_map(|(_peer, nonce)| nonce)
            .collect();
    
        let exec_id = Sha256::digest(&concatenated);

        exec_id.to_vec()
    }
    
    fn update_shares_and_complete(incomplete_key_share: IncompleteKeyShare<Secp256k1>, b: BigInt<4>, aux_info: Valid<DirtyAuxInfo>) -> Result<cggmp21::KeyShare<Secp256k1, SecurityLevel128>, Box<dyn Error>>{
        let mut dirty_shares = incomplete_key_share.into_inner();
        
        let b_bytes = b.to_bytes_be();
        let b_slice: [u8; 32] = b_bytes.try_into().unwrap();
        let b_scalar: Scalar<Secp256k1> = Scalar::<Secp256k1>::from_be_bytes_mod_order(b_slice);
        let b_nz = NonZero::from_scalar(b_scalar).unwrap();
      
        dirty_shares.x = NonZero::from_secret_scalar(SecretScalar::from_be_bytes((&dirty_shares.x * &b_nz).into_inner().to_be_bytes().as_bytes())?).unwrap();
    
        for pub_share in &mut dirty_shares.key_info.public_shares{
            *pub_share = NonZero::from_point(**pub_share * &b_nz).unwrap()
        }
    
        dirty_shares.key_info.shared_public_key = dirty_shares.key_info.shared_public_key* &b_nz;
    
        Ok(KeyShare::from_parts((dirty_shares.validate()?, aux_info))?)
    
    }
    
    pub async fn new(local_party_id: u16, n: u16) -> Result<MpcCurvy, Box<dyn Error>>{
        let network_setup = NetworkSetup::setup_swarm(local_party_id, n).await?;
        Ok(MpcCurvy { network_setup, n, local_party_id})
    }
    
    pub async fn run(mut self) -> Result<(), Box<dyn Error>>{

        let exec_id = self.gen_exec_id().await;
        let eid = ExecutionId::new(&exec_id);
      
        let swarm = Arc::new(Mutex::new(self.network_setup.swarm));
    
        let incoming: IncomingStream<NonThresholdMsg<Secp256k1, SecurityLevel128, Sha256>> = IncomingStream::new(Arc::clone(&swarm), self.network_setup.my_topic.clone(), self.network_setup.broadcast_topic.clone());
        let outgoing: OutgoingSink<NonThresholdMsg<Secp256k1, SecurityLevel128, Sha256>> = OutgoingSink::new(Arc::clone(&swarm), self.network_setup.broadcast_topic.clone());
    
        let delivery = (incoming, outgoing); 
        let party = round_based::MpcParty::connected(delivery);
    
        println!("Generating key shares...");
        let incomplete_key_share = cggmp21::keygen::<Secp256k1>(eid, self.local_party_id, self.n)
            .start(&mut OsRng, party)
            .await?;
    
        println!("Key shares generated...");
    
        let incoming = IncomingStream::new(Arc::clone(&swarm), self.network_setup.my_topic.clone(), self.network_setup.broadcast_topic.clone());
        let outgoing = OutgoingSink::new(Arc::clone(&swarm), self.network_setup.broadcast_topic.clone());
    
        let delivery = (incoming, outgoing); 
        let party = round_based::MpcParty::connected(delivery);
    
        let pregenerated_primes: PregeneratedPrimes<SecurityLevel128> = cggmp21::PregeneratedPrimes::generate(&mut OsRng);
    
        println!("Generating aux info...");
        let aux_info = cggmp21::aux_info_gen(eid, self.local_party_id, self.n, pregenerated_primes)
            .start(&mut OsRng, party)
            .await?;
        println!("Aux info generated...");
    
    
        let b = BigInt::from_str("4").unwrap();
        let key_share = Self::update_shares_and_complete(incomplete_key_share, b, aux_info)?;
    
        let mut parties_indexes_at_keygen = vec!(); 
        for i in 0..self.n{
            parties_indexes_at_keygen.push(i);
        }

        let data_to_sign: DataToSign<Secp256k1> = cggmp21::DataToSign::digest::<Sha256>(b"hello world"); 
    
        let incoming = IncomingStream::new(Arc::clone(&swarm), self.network_setup.my_topic.clone(), self.network_setup.broadcast_topic.clone());
        let outgoing = OutgoingSink::new(Arc::clone(&swarm), self.network_setup.broadcast_topic.clone());
    
        let delivery = (incoming, outgoing); 
        let party = round_based::MpcParty::connected(delivery);
    
        println!("Signing...");
        let _signature = cggmp21::signing(eid, self.local_party_id, &parties_indexes_at_keygen, &key_share)
            .sign(&mut OsRng, party, data_to_sign)
            .await?;
        println!("Signed!");
    
        Ok(())
    }
}
