use std::{error::Error, fs::File, hash::{DefaultHasher, Hash, Hasher}, io::{self, Read}, time::Duration};

use futures::StreamExt;
use libp2p::{gossipsub::{self, IdentTopic}, identity, mdns, noise, swarm::SwarmEvent, tcp, yamux, Swarm, SwarmBuilder};

use super::behaviour::{MyBehaviour, MyBehaviourEvent};

pub struct NetworkSetup{
    pub broadcast_topic: IdentTopic, 
    pub my_topic: IdentTopic, 
    pub swarm: Swarm<MyBehaviour>, 
}
impl NetworkSetup{
    pub async fn setup_swarm(local_party_id: u16,n: u16) -> Result<NetworkSetup, Box<dyn Error>>{
       
        let mut file = File::open(format!("src/data/party_{}_key.json", local_party_id)).expect("Cannot open file");
        let mut json_str = String::new(); 
        file.read_to_string(&mut json_str).expect("Cannot read file"); 
        let keypair_bytes: Vec<u8> = serde_json::from_str(&json_str).expect("Invalid json");
        let keypair  = identity::Keypair::from_protobuf_encoding(&keypair_bytes).expect("Cannot conveert to keypair");  
        
        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(), 
                noise::Config::new, 
                yamux::Config::default
            )?
            .with_behaviour(|key| {
        
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    message.data.hash(&mut s);
                    message.sequence_number.hash(&mut s);
                    message.source.hash(&mut s); 
                    gossipsub::MessageId::from(s.finish().to_be_bytes())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .max_transmit_size(4*1024*1024)
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .build()
                    .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

                let gossipsub:  gossipsub::Behaviour = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?; 
                Ok(MyBehaviour {gossipsub, mdns})
        })?
        .build();

        let broadcast_topic = IdentTopic::new("cggmp21/broadcast");
        let my_topic = IdentTopic::new(format!("cggmp21/party/{local_party_id}"));
        
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    
        swarm.behaviour_mut().gossipsub.subscribe(&broadcast_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&my_topic)?;

        let mut subscribed_peers = 0; 
        loop{
            match swarm.select_next_some().await{
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) =>{
                    for (peer_id, addr) in peers{
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        swarm.dial(addr.clone())?;
                        println!("Discovered peer: {} on address {}", peer_id, addr);
                    }
                }
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                    if topic == broadcast_topic.hash(){
                        println!("{} subscribed to {}", peer_id, topic);
                        subscribed_peers+=1; 
                    }
                }
                SwarmEvent::NewListenAddr { address , ..} => {
                    println!("Listening on {address}");
                }
                _ => {}
            }
            if subscribed_peers == n-1{
                break; 
            }
        }

        Ok(NetworkSetup { broadcast_topic, my_topic, swarm})
    }
}