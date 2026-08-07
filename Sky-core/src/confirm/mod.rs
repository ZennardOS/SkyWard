use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use anyhow::{Result, anyhow};
use sqlx::SqlitePool;

use crate::{contacts::get_public_key, identity::{Account, get_account_id}, messages::Message};



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryConfirm {
    pub version: u8,
    pub message_id: String,
    pub sender_account_id: String,
    pub receiver_account_id: String,
    pub delivered_date: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDeliveryConfirm {
    pub delivery: String,
    pub sign: String,
}

pub fn encode_delivery_confirm(delivery: &DeliveryConfirm) -> Result<String> {
    let bytes = serde_json::to_vec(delivery)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn decode_delivery_confirm(encoded: &str) -> Result<DeliveryConfirm> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    let payload = serde_json::from_slice(&bytes)?;
    Ok(payload)
}

pub fn encode_signed_delivery_confirm(signed_delivery: &SignedDeliveryConfirm) -> Result<String> {
    let bytes = serde_json::to_vec(signed_delivery)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn decode_signed_delivery_confirm(encoded: &str) -> Result<SignedDeliveryConfirm> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    let payload = serde_json::from_slice(&bytes)?;
    Ok(payload)
}

pub async fn apply_delivery_confirm(pool: &SqlitePool, account: &Account, delivery: &DeliveryConfirm) -> Result<Message> {
    if account.account_id != delivery.receiver_account_id {
        return Err(anyhow!("Confirm message is addressed to another account!"));
    }

    let message = sqlx::query_as::<_, (String, String, String, String, String, String, String, String)>(
        r#"
            SELECT
                message_id,
                chat_id,
                account_id,
                peer_account_id,
                direction,
                body,
                delivery_state,
                created_date
            FROM messages
            WHERE account_id = ? AND message_id = ?
"#,
    ).bind(&account.account_id).bind(&delivery.message_id).fetch_one(pool).await.map(|line| Message {
        message_id: line.0,
        chat_id: line.1,
        account_id: line.2,
        peer_account_id: line.3,
        direction: line.4,
        body: line.5,
        delivery_state: line.6,
        created_date: line.7,
    })?;

    if message.direction != "outgoing" {
        return Err(anyhow!("This message is not outgoing!"));
    }

    if message.peer_account_id != delivery.sender_account_id {
        return Err(anyhow!("sender id is doesn't match"));
    }

    let update_status = sqlx::query(
        r#"
            UPDATE messages
            SET delivery_state = 'delivered'
            WHERE message_id = ? AND account_id = ? AND peer_account_id = ? AND direction = 'outgoing'
"#,
    ).bind(&delivery.message_id).bind(&account.account_id).bind(&delivery.sender_account_id).execute(pool).await?;

    if update_status.rows_affected() != 1 {
        return Err(anyhow!("message is not updated!"));
    }

    let delivered_message = sqlx::query_as::<_, (String, String, String, String, String, String, String, String)>(
        r#"
        SELECT
                message_id,
                chat_id,
                account_id,
                peer_account_id,
                direction,
                body,
                delivery_state,
                created_date
            FROM messages
            WHERE account_id = ? AND message_id = ?
"#,
    ).bind(&account.account_id).bind(&delivery.message_id).fetch_one(pool).await.map(|line| Message {
        message_id: line.0,
        chat_id: line.1,
        account_id: line.2,
        peer_account_id: line.3,
        direction: line.4,
        body: line.5,
        delivery_state: line.6,
        created_date: line.7,
    })?;

    if delivered_message.delivery_state == "delivered" {
        return Ok(delivered_message);
    } else {
        return Err(anyhow!("message is not delivered!"));
    }
}

pub async fn verify_signed_delivery_confirm(pool: &SqlitePool, signed_delivery: &SignedDeliveryConfirm, account: &Account) -> Result<DeliveryConfirm> {
    let decoded_signed_delivery = decode_delivery_confirm(&signed_delivery.delivery)?;
    if decoded_signed_delivery.receiver_account_id != account.account_id {
        return Err(anyhow!("Confirm message is addressed to another account!"));
    }

    let saved_public_key = get_public_key(pool, account, &decoded_signed_delivery.sender_account_id).await?;
    let public_key_bytes = STANDARD.decode(&saved_public_key)?;
    let expected_id = get_account_id(&public_key_bytes);

    if expected_id != decoded_signed_delivery.sender_account_id {
        return Err(anyhow!("sender id doesn't match with "));
    }

    let public_key_arr: [u8; 32] = public_key_bytes.try_into().map_err(|_| anyhow!("public key lenght is incorrect!"))?;
    let public_key = VerifyingKey::from_bytes(&public_key_arr)?;
    let sign_bytes = STANDARD.decode(&signed_delivery.sign)?;
    let sign_arr: [u8; 64] = sign_bytes.try_into().map_err(|_| anyhow!("signature lenght is incorrect"))?;

    let signature = Signature::from_bytes(&sign_arr);
    public_key.verify(signed_delivery.delivery.as_bytes(), &signature).map_err(|err| anyhow!("signature verification is failed: {err}"))?;

    Ok(decoded_signed_delivery)
}

pub fn sign_delivery_confirm(deliver: &DeliveryConfirm, account: &Account) -> Result<SignedDeliveryConfirm> {
    let encoded = encode_delivery_confirm(deliver)?;
    let private_key_bytes = STANDARD.decode(&account.private_key)?;
    let private_key_arr: [u8; 32] = private_key_bytes.try_into().map_err(|_| anyhow!("private key lenght is incorrect"))?;

    let secret_key = SigningKey::from_bytes(&private_key_arr);
    let signature: Signature = secret_key.sign(encoded.as_bytes());


    Ok(SignedDeliveryConfirm {
        delivery: encoded,
        sign: STANDARD.encode(signature.to_bytes()),
    })
}

pub fn get_deliver_confirm(message: &Message, account: &Account) -> DeliveryConfirm {
    DeliveryConfirm {
        version: 1,
        message_id: message.message_id.clone(),
        sender_account_id: account.account_id.clone(),
        receiver_account_id: message.peer_account_id.clone(),
        delivered_date: Utc::now().to_rfc3339(),
    }
}
