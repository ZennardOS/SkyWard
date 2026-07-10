use anyhow::Result; 
use ed25519_dalek::{Signature, Signer, SigningKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::identity::Account;

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub version: u8, 
    pub account_id: String,
    pub public_key: String, 
    pub created_date: String, 
    pub token_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct InviteToken {
    pub payload: Payload, 
    pub sign: String,
}


pub fn token_generator(account: &Account) -> Result<String> {
    let private_key_bytes = base64::decode(&account.private_key)?;
    let private_key_arr: [u8; 32] = private_key_bytes.try_into().unwrap(); 

    let secret_key = SigningKey::from_bytes(&private_key_arr); 

    let payload = Payload {
        version: 1, 
        account_id: account.account_id.clone(), 
        public_key: account.public_key.clone(), 
        created_date: Utc::now().to_rfc3339(), 
        token_type: "multi_use".to_string(),
    };


    let payload_to_json = serde_json::to_vec(&payload)?;
    let signature: Signature = secret_key.sign(&payload_to_json); 

    let token = InviteToken {
        payload, 
        sign: base64::encode(signature.to_bytes()),
    };

    let token_to_json = serde_json::to_vec(&token)?;

    return Ok(URL_SAFE_NO_PAD.encode(token_to_json));

}