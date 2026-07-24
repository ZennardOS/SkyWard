use anyhow::{Ok, Result, anyhow};
use base64::engine::general_purpose::STANDARD;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::identity::{Account, get_account_id};
use crate::messages::Message;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverMessage {
    pub version: u8,
    pub message_id: String,
    pub sender_account_id: String,
    pub receiver_account_id: String,
    pub chat_id: String,
    pub created_date: String,
    pub payload_type: String,
    pub body: String,
}

pub struct SignedCoverMessage {
    pub cover: String,
    pub public_key: String,
    pub sign: String,
}

pub fn sign_cover(cover_message: &CoverMessage, account: &Account) -> Result<SignedCoverMessage> {
    let encoded = encode_cover_message(&cover_message)?;
    let private_key_bytes = STANDARD.decode(&account.private_key)?;
    let private_key_arr: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| anyhow!("private key length is incorrect"))?;

    let secret_key = SigningKey::from_bytes(&private_key_arr);
    let signature: Signature = secret_key.sign(encoded.as_bytes());

    Ok(SignedCoverMessage {
        cover: encoded,
        public_key: account.public_key.clone(),
        sign: STANDARD.encode(signature.to_bytes()),
    })
}

pub fn verify_sign_cover(signed_cover: &SignedCoverMessage) -> Result<CoverMessage> {
    let decoded_signed_cover_message = decode_cover_message(&signed_cover.cover)?;
    let public_key_bytes = STANDARD.decode(&signed_cover.public_key)?;
    let expected_id = get_account_id(&public_key_bytes);

    if decoded_signed_cover_message.sender_account_id != expected_id {
        return Err(anyhow!("sender id is not correct"));
    }

    let public_key_arr: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key lenght is incorrect!"))?;

    let public_key = VerifyingKey::from_bytes(&public_key_arr)?;

    let sign_bytes = STANDARD.decode(&signed_cover.sign)?;
    let sign_arr: [u8; 64] = sign_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Lenght line is incorrect!"))?;
    let signature = Signature::from_bytes(&sign_arr);

    public_key
        .verify(&signed_cover.cover.as_bytes(), &signature)
        .map_err(|e| anyhow!("Signature verification failed: {}", e))?;

    Ok(decoded_signed_cover_message)
}

pub fn encode_cover_message(cover_message: &CoverMessage) -> Result<String> {
    let bytes = serde_json::to_vec(cover_message)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn decode_cover_message(encoded: &str) -> Result<CoverMessage> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    let payload = serde_json::from_slice(&bytes)?;
    Ok(payload)
}

pub fn get_cover_message(message: &Message) -> CoverMessage {
    CoverMessage {
        version: 1,
        message_id: message.message_id.clone(),
        sender_account_id: message.account_id.clone(),
        receiver_account_id: message.peer_account_id.clone(),
        chat_id: message.chat_id.clone(),
        created_date: message.created_date.clone(),
        payload_type: "text".to_string(),
        body: message.body.clone(),
    }
}
