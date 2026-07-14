use crate::identity::{Account, get_account_id};
use anyhow::{Result, anyhow};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
    pub version: u8,
    pub account_id: String,
    pub public_key: String,
    pub created_date: String,
    pub token_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteToken {
    pub payload: String,
    pub sign: String,
}

pub fn verify_invite_token(token: &str) -> Result<Payload> {
    let decoded_bytes = URL_SAFE_NO_PAD.decode(token)?;
    let invite_token: InviteToken = serde_json::from_slice(&decoded_bytes)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(&invite_token.payload)?;
    let payload: Payload = serde_json::from_slice(&payload_bytes)?;

    if payload.version != 1 {
        return Err(anyhow!("unsupported version!"));
    }

    if payload.token_type != "multi_use" {
        return Err(anyhow!("unsupported token type!"));
    }

    let public_key_bytes = STANDARD.decode(&payload.public_key)?;
    let pub_key_arr: [u8; 32] = public_key_bytes
        .clone()
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key lenght is incorrect!"))?;
    let public_key = VerifyingKey::from_bytes(&pub_key_arr)?;
    let sign_bytes = STANDARD.decode(&invite_token.sign)?;
    let sign_arr: [u8; 64] = sign_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Lenght line is incorrect!"))?;
    let signature = Signature::from_bytes(&sign_arr);
    public_key.verify(&payload_bytes, &signature)?;

    let expected_id = get_account_id(&public_key_bytes);
    if payload.account_id != expected_id {
        return Err(anyhow!("account_id is incorrect!"));
    }

    Ok(payload)
}

pub fn token_generator(account: &Account) -> Result<String> {
    let private_key_bytes = STANDARD.decode(&account.private_key)?;
    let private_key_arr: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| anyhow!("private key length is incorrect"))?;

    let secret_key = SigningKey::from_bytes(&private_key_arr);

    let derived_public_key = secret_key.verifying_key();
    let derived_public_key_enc = STANDARD.encode(derived_public_key.to_bytes());

    if derived_public_key_enc != account.public_key {
        return Err(anyhow!("private key does not match to public key!"));
    }

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
        payload: URL_SAFE_NO_PAD.encode(&payload_to_json),
        sign: STANDARD.encode(signature.to_bytes()),
    };

    let token_to_json = serde_json::to_vec(&token)?;

    return Ok(URL_SAFE_NO_PAD.encode(token_to_json));
}
