use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct KeyGenerationReqBody {
    pub exec_id: &'static[u8],
    pub n: Option<u16>,
    pub local_party_id: Option<u16>,
    pub t: u16,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct SignTransactionReqBody {
    pub exec_id: &'static[u8],
    pub n: Option<u16>,
    pub local_party_id: Option<u16>,
    pub incomplete_key_share: String,
    pub entry: String,
    pub viewing_sk: String,
    pub view_tag_version: usize,
    pub viewtag: String,
}