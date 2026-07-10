use anyhow::Result; 
use sqlx::SqlitePool;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _; 
use chrono::Utc; 

pub fn get_account_id(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key); 
    base64::encode(&hash[..16])
}



pub struct Account {
    pub account_id: String, 
    pub public_key: String, 
    pub private_key: String,
}

pub async fn load_or_create(pool: &SqlitePool) -> Result<Account> {
    if let Some(line) = sqlx::query_as::<_, (String, String, String)>(
        "SELECT account_id, public_key, private_key FROM accounts LIMIT 1"
    )
    .fetch_optional(pool).await? {
        return Ok(Account {
            account_id: line.0, 
            public_key: line.1, 
            private_key: line.2,
        });
    }
    let mut rng = rand::thread_rng();
    let secret_key = SigningKey::generate(&mut rng); 
    let open_key: VerifyingKey = secret_key.verifying_key();

    let public_key_bytes = secret_key.to_bytes(); 
    let private_key_bytes = open_key.to_bytes(); 

    let account_id = get_account_id(&public_key_bytes); 

    let public_key = base64::encode(public_key_bytes); 
    let private_key = base64::encode(private_key_bytes); 


    sqlx::query("INSERT INTO accounts (account_id, public_key, private_key, created_date) VALUES (?, ?, ?, ?)",).bind(&account_id).bind(&public_key).bind(&private_key).bind(Utc::now().to_rfc3339()).execute(pool).await?; 

    return Ok(Account {
        account_id, 
        public_key, 
        private_key,
    });
}
