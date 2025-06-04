use std::{marker::PhantomData, sync::{Arc, Mutex}, task::Poll};
use cggmp21::{round_based::{Incoming, MessageType}, signing::msg::Msg, supported_curves::Secp256k1, KeygenError};
use futures::{Stream, StreamExt};
use libp2p::{ gossipsub::{self, IdentTopic}, swarm::SwarmEvent, Swarm};
use sha2::Sha256;
use crate::off_chain::network::{behaviour::{MyBehaviour, MyBehaviourEvent}, hash_map::PEER_TO_PARTY_MAP};

pub struct IncomingStream<T>{
    swarm: Arc<Mutex<Swarm<MyBehaviour>>>, 
    my_topic: IdentTopic, 
    broadcast_topic: IdentTopic, 
    _phantom: PhantomData<T>
}
impl<T> IncomingStream<T>{
    pub fn new(swarm: Arc<Mutex<Swarm<MyBehaviour>>>, my_topic: IdentTopic, broadcast_topic: IdentTopic) -> IncomingStream<T>{
        IncomingStream { swarm, my_topic, broadcast_topic, _phantom: PhantomData}   
    }
}

#[allow(dead_code)]
fn extract_round(msg: &Msg<Secp256k1, Sha256>) -> usize{
    match msg{
        Msg::ReliabilityCheck(_) => 1, 
        Msg::Round1a(_) => 2, 
        Msg::Round1b(_) => 3, 
        Msg::Round2(_) => 4, 
        Msg::Round3(_) => 5, 
        Msg::Round4(_) => 6, 
    }
}

impl<T> Stream for IncomingStream<T>
where T: serde::de::DeserializeOwned + Unpin
{
    type Item = Result<Incoming<T>, KeygenError>; // <- generalize error 

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
       
        let this = self.get_mut();

        let mut swarm = match this.swarm.lock() {
            Ok(swarm) => swarm,
            Err(_) => {
                println!("Cannot lock"); 
                return Poll::Pending
            }
        , 
        };
        
        match swarm.poll_next_unpin(cx){
          
            Poll::Ready(Some(event)) => {
                if let SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message_id, message })) = event{
                    match bincode::deserialize::<T>(&message.data) {
                        Ok(msg) => {

                            let msg_type = if message.topic == this.broadcast_topic.clone().into(){
                                MessageType::Broadcast
                            }else if message.topic == this.my_topic.clone().into(){
                                MessageType::P2P
                            }else{
                                println!("Wrong message type");
                                drop(swarm);
                                return Poll::Pending;
                            }; 
                            
                            let sender = match PEER_TO_PARTY_MAP.get(&propagation_source.to_string()) {
                                Some(&party_id) => party_id,
                                None => {
                                    println!("No party id found");
                                    drop(swarm);
                                    return Poll::Pending;
                                }
                            };


                            let bytes = message_id.0; 
                            if bytes.len() > 8 {
                                println!("Message id too long");
                                drop(swarm);
                                return Poll::Pending;
                            }

                            let mut byte_slice = [0u8; 8]; 
                            for (i, &byte) in bytes.iter().enumerate(){
                                byte_slice[i] = byte; 
                            }
                            let id = u64::from_be_bytes(byte_slice);

                            let incoming = Incoming{
                                id, 
                                sender, 
                                msg_type, 
                                msg 
                            };

                            println!("Received message from {sender}, message type {msg_type:?}, message_id :{}", id);
                            drop(swarm);
                            Poll::Ready(Some(Ok(incoming)))
                           
                        },   
                        Err(_) => {
                            println!("Cannot deserialize msg");
                            drop(swarm);
                            return Poll::Pending;
                        }
                    }
                }else{
                    drop(swarm);
                    return Poll::Pending;
                }
            }, 
            Poll::Ready(None) => {
                drop(swarm);
                return Poll::Ready(None);
            },
            Poll::Pending => {
                drop(swarm);
                return Poll::Pending;
            },
        }
    }
}