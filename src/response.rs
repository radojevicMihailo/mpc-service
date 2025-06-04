use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct KeyGenerationResponse {
    pub incomplete_key_share: String
}

#[derive(Serialize, Debug)]
pub struct SignTransactionResponse {
    pub signature: String
}