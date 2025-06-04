use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct KeyGenerationReqBody {
    pub n: Option<u16>,
    pub local_party_id: Option<u16>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct SignTransactionReqBody {
    pub n: Option<u16>,
    pub local_party_id: Option<u16>,
    pub incomplete_key_share: String,
}