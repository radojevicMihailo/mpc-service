use core::panic;
use std::{marker::PhantomData, sync::{Arc, Mutex}, task::Poll};

use cggmp21::{round_based::{MessageDestination, Outgoing}, KeygenError};
use futures::Sink;
use libp2p::{gossipsub::IdentTopic, Swarm};

use crate::off_chain::network::behaviour::MyBehaviour;

pub struct OutgoingSink<T>{
    swarm: Arc<Mutex<Swarm<MyBehaviour>>>, 
    broadcast_topic: IdentTopic, 
    _phantom: PhantomData<T>,
}

impl<T> OutgoingSink<T>{
    pub fn new(swarm: Arc<Mutex<Swarm<MyBehaviour>>>, broadcast_topic: IdentTopic) -> OutgoingSink<T>{
        OutgoingSink{
            swarm,  
            broadcast_topic, 
            _phantom: PhantomData
        }
    }
}

impl<T> Sink<Outgoing<T>> for OutgoingSink<T>
where 
    T: serde::Serialize + Unpin
{
    type Error = KeygenError;
    
    fn poll_ready(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    
    fn start_send(self: std::pin::Pin<&mut Self>, item: Outgoing<T>) -> Result<(), Self::Error> {
        let serialized_msg = bincode::serialize(&item.msg).expect("Cannot serialize msg");
        
        let this = self.get_mut();

        let mut swarm_lock =  this.swarm.lock().expect("Cannot lock swarm");

        if item.is_broadcast(){
            let broadcast_topic = this.broadcast_topic.clone();
            swarm_lock.behaviour_mut().gossipsub.publish(broadcast_topic, serialized_msg).expect("Cannot publish");
            println!("Publishing to broadcast"); 
        }else{
            match item.recipient{
                MessageDestination::OneParty(party_index) => {
                    let party_topic = IdentTopic::new(format!("cggmp21/party/{party_index}"));    
                    swarm_lock.behaviour_mut().gossipsub.publish(party_topic, serialized_msg).expect("Cannot publish");
                    println!("Sending to party {}", party_index);
                }, 
                MessageDestination::AllParties => {
                    drop(swarm_lock);
                    panic!("invalid message");
                  
                }
            }
        }
        
        drop(swarm_lock);
        Ok(())
    }
    
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    
    fn poll_close(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}