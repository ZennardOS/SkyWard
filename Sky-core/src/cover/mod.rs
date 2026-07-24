use anyhow::{Result, anyhow};
use base64::engine::general_purpose::STANDARD;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use crate::contacts::get_public_key;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCoverMessage {
    pub cover: String,
    pub sign: String,
}

pub fn sign_cover(cover_message: &CoverMessage, account: &Account) -> Result<SignedCoverMessage> {
    let encoded = encode_cover_message(cover_message)?;
    let private_key_bytes = STANDARD.decode(&account.private_key)?;
    let private_key_arr: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| anyhow!("private key lenght is incorrect"))?;

    let secret_key = SigningKey::from_bytes(&private_key_arr);
    let signature: Signature = secret_key.sign(encoded.as_bytes());

    Ok(SignedCoverMessage {
        cover: encoded,
        sign: STANDARD.encode(signature.to_bytes()),
    })
}

pub async fn verify_signed_cover(pool: &SqlitePool, signed_cover: &SignedCoverMessage, my_account: &Account) -> Result<CoverMessage> {
    let decoded_signed_cover_message = decode_cover_message(&signed_cover.cover)?;
    if decoded_signed_cover_message.receiver_account_id != my_account.account_id {
        return Err(anyhow!("message is addressed to another account!"));
    }

    let saved_public_key = get_public_key(pool, my_account, &decoded_signed_cover_message.sender_account_id).await?;
    let public_key_bytes = STANDARD.decode(&saved_public_key)?;
    let expected_sender_id = get_account_id(&public_key_bytes);

    if decoded_signed_cover_message.sender_account_id != expected_sender_id {
        return Err(anyhow!("sender id doesn't match with expected id"));
    }

    let public_key_arr: [u8; 32] = public_key_bytes.try_into().map_err(|_| anyhow!("public key lenght is incorrect!"))?;

    let public_key = VerifyingKey::from_bytes(&public_key_arr)?;

    let sign_bytes = STANDARD.decode(&signed_cover.sign)?;
    let sign_arr: [u8; 64] = sign_bytes.try_into().map_err(|_| anyhow!("signature lenght is incorrect"))?;

    let signature = Signature::from_bytes(&sign_arr);

    public_key.verify(signed_cover.cover.as_bytes(), &signature).map_err(|err| anyhow!("signature verification is failed: {err}"))?;

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
