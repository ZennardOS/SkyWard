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
        INSERT INTO Chat (
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

    todo!("WILL DO");
}
