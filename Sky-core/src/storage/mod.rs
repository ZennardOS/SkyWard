use anyhow::Result; 
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool}; 

pub async fn connect() -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new().max_connections(5).connect("sqlite://./sky.db?mode=rwc").await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY, 
            public_key TEXT NOT NULL, 
            private_key TEXT NOT NULL, 
            created_date TEXT NOT NULL
        );
    "#,

    ).execute(&pool).await?;

    Ok(pool)
}