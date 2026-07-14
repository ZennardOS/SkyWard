use anyhow::{Result, anyhow};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::identity::Account;
use crate::invites::verify_invite_token;

#[derive(Debug)]
pub struct Contact {
    pub contact_id: String,
    pub account_id: String,
    pub peer_account_id: String,
    pub peer_public_key: String,
    pub nickname: Option<String>,
    pub trusted: String,
    pub created_date: String,
}

pub async fn add_contact(
    pool: &SqlitePool,
    my_account: &Account,
    token: &str,
    nickname: Option<String>,
) -> Result<Contact> {
    let payload = verify_invite_token(token)?;
    if payload.account_id == my_account.account_id {
        return Err(anyhow!("you cannot add yourself!"));
    }

    let contact_id = Uuid::new_v4().to_string();
    let trusted = "trusted".to_string();
    let created_date = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
                INSERT INTO contacts (
                    contact_id,
                    account_id,
                    peer_account_id,
                    peer_public_key,
                    nickname,
                    trusted,
                    created_date
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_id, peer_account_id) DO UPDATE SET
                    peer_public_key = excluded.peer_public_key,
                    nickname = COALESCE(excluded.nickname, contacts.nickname),
                    trusted = excluded.trusted
        "#,
    )
    .bind(&contact_id)
    .bind(&my_account.account_id)
    .bind(&payload.account_id)
    .bind(&payload.public_key)
    .bind(&nickname)
    .bind(&trusted)
    .bind(&created_date)
    .execute(pool)
    .await?;

    let line = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            String,
        ),
    >(
        r#"
        SELECT
            contact_id,
            account_id,
            peer_account_id,
            peer_public_key,
            nickname,
            trusted,
            created_date
        FROM contacts
        WHERE account_id = ? AND peer_account_id = ?
        "#,
    )
    .bind(&my_account.account_id)
    .bind(&payload.account_id)
    .fetch_one(pool)
    .await?;

    return Ok(Contact {
        contact_id: line.0,
        account_id: line.1,
        peer_account_id: line.2,
        peer_public_key: line.3,
        nickname: line.4,
        trusted: line.5,
        created_date: line.6,
    });
}

pub async fn list_contacts(pool: &SqlitePool, my_account: &Account) -> Result<Vec<Contact>> {
    let lines = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            String,
        ),
    >(
        r#"
        SELECT
            contact_id,
            account_id,
            peer_account_id,
            peer_public_key,
            nickname,
            trusted,
            created_date
        FROM contacts
        WHERE account_id = ?
        ORDER BY trusted DESC
        "#,
    )
    .bind(&my_account.account_id)
    .fetch_all(pool)
    .await?;

    let contacts: Vec<Contact> = lines
        .into_iter()
        .map(|line| Contact {
            contact_id: line.0,
            account_id: line.1,
            peer_account_id: line.2,
            peer_public_key: line.3,
            nickname: line.4,
            trusted: line.5,
            created_date: line.6,
        })
        .collect();

    Ok(contacts)
}
