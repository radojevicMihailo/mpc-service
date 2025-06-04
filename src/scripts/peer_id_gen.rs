use libp2p::{identity, PeerId};

fn main(){
    let keypair = identity::Keypair::generate_ed25519(); 
    
    let json = serde_json::to_string(&keypair.to_protobuf_encoding().unwrap()).unwrap(); 
    println!("{:?}", json);

    let peer_id = PeerId::from(keypair.public());
    println!("{:?}", peer_id);
}