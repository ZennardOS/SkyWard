use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::chats::Chat;
use crate::identity::Account;

#[derive(Debug)]
pub struct Message {
    pub message_id: String,
    pub chat_id: String,
    pub account_id: String,
    pub peer_account_id: String,
    pub direction: String,
    pub body: String,
    pub delivery_state: String,
    pub created_date: String,
}

pub async fn outgoing_message_saver(
    pool: &SqlitePool,
    my_account: &Account,
    chat: &Chat,
    body: &str,
) -> Result<Message> {
    let message_id = Uuid::new_v4().to_string();
    let created_date = Utc::now().to_rfc3339();
    let direction = "outgoing";
    let delivery_state = "local";

    sqlx::query(
        r#"
            INSERT INTO messages (
                message_id,
                chat_id,
                account_id,
                peer_account_id,
                direction,
                body,
                delivery_state,
                created_date
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&message_id)
    .bind(&chat.chat_id)
    .bind(&my_account.account_id)
    .bind(&chat.peer_account_id)
    .bind(direction)
    .bind(body)
    .bind(delivery_state)
    .bind(&created_date)
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        UPDATE chats
        SET last_message_date = ?
        WHERE chat_id = ? AND account_id = ?
        "#,
    )
    .bind(&created_date)
    .bind(&chat.chat_id)
    .bind(&my_account.account_id)
    .execute(pool)
    .await?;

    Ok(Message {
        message_id,
        chat_id: chat.chat_id.clone(),
        account_id: my_account.account_id.clone(),
        peer_account_id: chat.peer_account_id.clone(),
        direction: direction.to_string(),
        body: body.to_string(),
        delivery_state: delivery_state.to_string(),
        created_date,
    })
}

pub async fn list_messages(
    pool: &SqlitePool,
    my_account: &Account,
    chat_id: &str,
) -> Result<Vec<Message>> {
    let lines = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        ),
    >(
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
            WHERE account_id = ? AND chat_id = ?
            ORDER BY created_date
        "#,
    )
    .bind(&my_account.account_id)
    .bind(chat_id)
    .fetch_all(pool)
    .await?;

    let messages: Vec<Message> = lines
        .into_iter()
        .map(|line| Message {
            message_id: line.0,
            chat_id: line.1,
            account_id: line.2,
            peer_account_id: line.3,
            direction: line.4,
            body: line.5,
            delivery_state: line.6,
            created_date: line.7,
        })
        .collect();

    Ok(messages)
}
