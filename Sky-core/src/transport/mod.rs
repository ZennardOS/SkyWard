use crate::confirm;
use crate::cover;
use crate::identity::{self, Account};
use crate::messages;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportPacket {
    pub version: u8,
    pub packet_id: String,
    pub receiver_account_id: String,
    pub packet_type: String,
    pub payload: String,
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

            Ok(())
        }
        "DeliveryMessage" => {
            let signed = confirm::decode_signed_delivery_confirm(&packet.payload)?;
            let verified = confirm::verify_signed_delivery_confirm(pool, &signed, account).await?;
            let delivery_message =
                confirm::apply_delivery_confirm(pool, account, &verified).await?;
            println!("Type Delivery message");
            println!("message_id: {}", delivery_message.message_id);
            Ok(())
        }

        _ => return Err(anyhow!("unknown packet type")),
    }
}

pub async fn send_packet(packet: &TransportPacket) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client.post("http://localhost:8080/packets").json(packet).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!("responce status is not success {}", response.status()));
    }

    Ok(())


}

pub async fn fetch_packet(account_id: &str) -> Result<Vec<TransportPacket>> {
    let client = reqwest::Client::new();

    let response: reqwest::Response = client.get("http://localhost:8080/packets").query(&[("account_id", account_id)]).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!("relay returned status: {}", response.status()));
    }

    let packets = response.json::<Vec<TransportPacket>>().await?;

    Ok(packets)


}
