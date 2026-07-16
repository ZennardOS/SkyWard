use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::contacts::Contact;
use crate::identity::Account;

#[derive(Debug)]
pub struct Chat {
    pub chat_id: String,
    pub account_id: String,
    pub contact_id: String,
    pub peer_account_id: String,
    pub created_date: String,
    pub last_message_date: Option<String>,
}

pub async fn get_chat(pool: &SqlitePool, my_account: &Account, contact: &Contact) -> Result<Chat> {
    let chat_id = Uuid::new_v4().to_string();
    let created_date = Utc::now().to_rfc3339();

    sqlx::query(r#"
        INSERT INTO chats (
            chat_id,
            account_id,
            contact_id,
            peer_account_id,
            created_date,
            last_message_date
        )
        VALUES (?, ?, ?, ?, ?, NULL)
        ON CONFLICT(account_id, peer_account_id) DO NOTHING
"#,
    ).bind(&chat_id).bind(&my_account.account_id).bind(&contact.contact_id).bind(&contact.peer_account_id).bind(&created_date).execute(pool).await?;

    let line = sqlx::query_as::<_, (String, String, String, String, String, Option<String>)>(
        r#"
        SELECT
            chat_id,
            account_id,
            contact_id,
            peer_account_id,
            created_date,
            last_message_date
        FROM chats
        WHERE account_id = ? AND peer_account_id = ?
"#,
    ).bind(&my_account.account_id).bind(&contact.peer_account_id).fetch_one(pool).await?;

    return Ok(Chat {
        chat_id: line.0,
        account_id: line.1,
        contact_id: line.2,
        peer_account_id: line.3,
        created_date: line.4,
        last_message_date: line.5,
    });

}


pub async fn list_chats(pool: &SqlitePool, my_account: &Account) -> Result<Vec<Chat>> {
    let lines = sqlx::query_as::<_, (String, String, String, String, String, Option<String>)>(
        r#"
            SELECT
                chat_id,
                account_id,
                contact_id,
                peer_account_id,
                created_date,
                last_message_date
            FROM chats
            WHERE account_id = ?
            ORDER BY COALESCE(last_message_date, created_date) DESC
"#,
    ).bind(&my_account.account_id).fetch_all(pool).await?;

    let chats: Vec<Chat> = lines.into_iter().map(|line| Chat {
        chat_id: line.0,
        account_id: line.1,
        contact_id: line.2,
        peer_account_id: line.3,
        created_date: line.4,
        last_message_date: line.5,
    })
                                            .collect();

    Ok(chats)

}
