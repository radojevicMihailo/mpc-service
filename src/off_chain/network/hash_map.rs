use phf::phf_map;

pub static PEER_TO_PARTY_MAP: phf::Map<&'static str, u16> = phf_map!(
    "12D3KooWEXBz3x6rbVF7pkNJGgQ1dr1CNb56ERJ5qPpRcTMzQALs" => 0, 
    "12D3KooWA9VywoaZHDPTV76xqipm6ejSRPRh4BUqZy2TDz1MQJik" => 1, 
    "12D3KooWSCfEDp23JmAACJ7kc8SuJXfMR3WBQsZcUUpLyKtnPhGZ" => 2,
);

pub static PARTY_TO_PEER_MAP: phf::Map<u16, &'static str> = phf_map!(
    0u16 => "12D3KooWEXBz3x6rbVF7pkNJGgQ1dr1CNb56ERJ5qPpRcTMzQALs",
    1u16 => "12D3KooWA9VywoaZHDPTV76xqipm6ejSRPRh4BUqZy2TDz1MQJik",
    2u16 => "12D3KooWSCfEDp23JmAACJ7kc8SuJXfMR3WBQsZcUUpLyKtnPhGZ"
);