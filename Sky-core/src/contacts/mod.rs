use crate::identity::Account;
use crate::invites::verify_invite_token;
use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Debug)]
pub struct Contact {
    pub contact_id: String,
    pub account_id: String,
    pub peer_account_id: String,
    pub peer_public_key: String,
    pub peer_encryption_public_key: String,
    pub nickname: Option<String>,
    pub trusted: String,
    pub created_date: String,
}

pub async fn get_public_key(
    pool: &SqlitePool,
    my_account: &Account,
    peer_account_id: &str,
) -> Result<String> {
    let public_key = sqlx::query_scalar::<_, String>(
        r#"
        SELECT peer_public_key
        FROM contacts
        WHERE account_id = ? AND peer_account_id = ?
"#,
    )
    .bind(&my_account.account_id)
    .bind(peer_account_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("Contact public key not found for peer: {}", peer_account_id))?;

    Ok(public_key)
}

pub async fn get_peer_encryption_public_key(
    pool: &SqlitePool,
    my_account: &Account,
    peer_account_id: &str,
) -> Result<String> {
    let public_key = sqlx::query_scalar::<_, String>(
        r#"
        SELECT peer_encryption_public_key
        FROM contacts
        WHERE account_id = ? AND peer_account_id = ?
"#,
    )
    .bind(&my_account.account_id)
    .bind(peer_account_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| {
        anyhow!(
            "Contact encryption public key not found for peer: {}",
            peer_account_id
        )
    })?;

    Ok(public_key)
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
                    peer_encryption_public_key,
                    nickname,
                    trusted,
                    created_date
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_id, peer_account_id) DO UPDATE SET
                    peer_public_key = excluded.peer_public_key,
                    peer_encryption_public_key = excluded.peer_encryption_public_key,
                    nickname = COALESCE(excluded.nickname, contacts.nickname),
                    trusted = excluded.trusted
        "#,
    )
    .bind(&contact_id)
    .bind(&my_account.account_id)
    .bind(&payload.account_id)
    .bind(&payload.public_key)
    .bind(&payload.encryption_public_key)
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
            peer_encryption_public_key,
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
        peer_encryption_public_key: line.4,
        nickname: line.5,
        trusted: line.6,
        created_date: line.7,
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
            peer_encryption_public_key,
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
            peer_encryption_public_key: line.4,
            nickname: line.5,
            trusted: line.6,
            created_date: line.7,
        })
        .collect();

    Ok(contacts)
}
