use anyhow::Result;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

pub async fn connect() -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite://./sky.db?mode=rwc")
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            created_date TEXT NOT NULL
        );
    "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
    CREATE TABLE IF NOT EXISTS contacts (
        contact_id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        peer_account_id TEXT NOT NULL,
        peer_public_key TEXT NOT NULL,
        nickname TEXT,
        trusted TEXT NOT NULL,
        created_date TEXT NOT NULL,

        UNIQUE(account_id, peer_account_id)
    );
    "#,
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}
