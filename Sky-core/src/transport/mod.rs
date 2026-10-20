use crate::confirm;
use crate::cover;
use crate::identity::{self, Account};
use crate::messages;
use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportPacket {
    pub version: u8,
    pub packet_id: String,
    pub receiver_account_id: String,
    pub packet_type: String,
    pub payload: String,
}

#[derive(Debug, Deserialize)]
struct VeResponse {
    number: String,
}

pub fn encode_transport_packet(packet: &TransportPacket) -> Result<String> {
    Ok(serde_json::to_string(packet)?)
}

pub fn decode_transport_packet(payload: &str) -> Result<TransportPacket> {
    Ok(serde_json::from_str(payload)?)
}

pub async fn transporting_packet(
    pool: &SqlitePool,
    account: &Account,
    packet: &TransportPacket,
) -> Result<()> {
    if packet.receiver_account_id != account.account_id {
        return Err(anyhow!("transport packet is addressed to another account!"));
    }
    if packet.version != 1 {
        return Err(anyhow!("unsupported transport version: {}", packet.version));
    }

    match packet.packet_type.as_str() {
        "message" => {
            let signed = cover::decode_signed_cover_message(&packet.payload)?;
            let mut verified = cover::verify_signed_cover(pool, &signed, account).await?;
            let shared = identity::get_secret(pool, account, &verified.sender_account_id).await?;
            let key = identity::get_message_key(&shared)?;
            let plaintext = cover::decrypt_message(&key, &verified.body)?;
            verified.body = plaintext;
            let message = messages::incoming_message_saver(pool, account, &verified).await?;

            println!("Type: Incoming message");
            println!("message_id: {}", message.message_id);
            println!("from: {}", message.peer_account_id);
            println!("body: {}", message.body);

            let delivery = confirm::get_deliver_confirm(&message, account);
            let signed_delivery = confirm::sign_delivery_confirm(&delivery, account)?;
            let encoded_delivery = confirm::encode_signed_delivery_confirm(&signed_delivery)?;

            let delivery_packet = TransportPacket {
                version: 1,
                packet_id: Uuid::new_v4().to_string(),
                receiver_account_id: message.peer_account_id.clone(),
                packet_type: "DeliveryMessage".to_string(),
                payload: encoded_delivery,
            };

            send_packet(account, &delivery_packet).await?;

            println!(
                "Delivery confirm was sended message with id: {}",
                delivery_packet.packet_id
            );

            Ok(())
        }
        "DeliveryMessage" => {
            let signed = confirm::decode_signed_delivery_confirm(&packet.payload)?;
            let verified = confirm::verify_signed_delivery_confirm(pool, &signed, account).await?;
            let delivery_message =
                confirm::apply_delivery_confirm(pool, account, &verified).await?;
            println!("Type: Delivery message");
            println!("message_id: {}", delivery_message.message_id);
            Ok(())
        }

        _ => return Err(anyhow!("unknown packet type")),
    }
}

fn sign_relay_auth(account: &Account, number: &str, path: &str, method: &str) -> Result<String> {
    let private_key_bytes = STANDARD.decode(&account.private_key)?;
    let private_key_array: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| anyhow!("invalid private key lenght!"))?;

    let private_key = SigningKey::from_bytes(&private_key_array);

    let auth_message = format!("sky-relay-auth-v1\n{}\n{}\n{}", number, method, path);
    let signature = private_key.sign(auth_message.as_bytes());

    Ok(STANDARD.encode(signature.to_bytes()))
}

pub async fn send_packet(account: &Account, packet: &TransportPacket) -> Result<()> {
    let client = reqwest::Client::new();
    let number = get_number(&client, account).await?;
    let sign = sign_relay_auth(account, &number, "/packets", "POST")?;

    let response = client
        .post("http://localhost:8080/packets")
        .header("X-Account-ID", &account.account_id)
        .header("X-Public-Key", &account.public_key)
        .header("X-Number", &number)
        .header("X-Signature", &sign)
        .json(packet)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "responce status is not success {}",
            response.status()
        ));
    }

    Ok(())
}

pub async fn fetch_packet(account: &Account) -> Result<Vec<TransportPacket>> {
    let client = reqwest::Client::new();

    let number = get_number(&client, account).await?;
    let sign = sign_relay_auth(account, &number, "/packets", "GET")?;

    let response: reqwest::Response = client
        .get("http://localhost:8080/packets")
        .query(&[("account_id", account.account_id.as_str())])
        .header("X-Public-Key", &account.public_key)
        .header("X-Number", &number)
        .header("X-Signature", &sign)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!("relay returned status: {}", response.status()));
    }

    let packets = response.json::<Vec<TransportPacket>>().await?;

    Ok(packets)
}

pub async fn ack_packet(account: &Account, packet_id: &str) -> Result<()> {
    let client = reqwest::Client::new();

    let number = get_number(&client, account).await?;
    let path = format!("/packets/{}", packet_id);

    let signature = sign_relay_auth(account, &number, &path, "DELETE")?;

    let url = format!("http://localhost:8080{}", path);

    let response = client
        .delete(url)
        .query(&[("account_id", account.account_id.as_str())])
        .header("X-Public-Key", &account.public_key)
        .header("X-Number", &number)
        .header("X-Signature", &signature)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!("relay returned status: {}", response.status()));
    }

    Ok(())
}

async fn get_number(client: &reqwest::Client, account: &Account) -> Result<String> {
    let response = client
        .get("http://localhost:8080/auth/verification")
        .query(&[("account_id", account.account_id.as_str())])
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!("failed status: {}", response.status()));
    }

    let response = response.json::<VeResponse>().await?;
    Ok(response.number)
}
