use anyhow::Result;
use anyhow::anyhow;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::contacts;

pub fn get_account_id(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    STANDARD.encode(&hash[..16])
}

pub struct Account {
    pub account_id: String,
    pub public_key: String,
    pub private_key: String,
    pub encryption_public_key: String,
    pub encryption_private_key: String,
}

pub fn get_message_key(general_secret: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, general_secret);

    let mut key = [0u8; 32];
    hk.expand(b"sky-message-key-v1", &mut key)
        .map_err(|_| anyhow!("expanding is failed!"))?;

    Ok(key)
}

pub async fn get_secret(
    pool: &SqlitePool,
    my_account: &Account,
    peer_account_id: &str,
) -> Result<[u8; 32]> {
    let private_key_bytes = STANDARD.decode(&my_account.encryption_private_key)?;
    let private_key_arr: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| anyhow!("encryption private key length is incorrect!"))?;

    let peer_public_key =
        contacts::get_peer_encryption_public_key(pool, my_account, peer_account_id).await?;

    let peer_public_key_bytes = STANDARD.decode(peer_public_key)?;

    let peer_public_key_arr: [u8; 32] = peer_public_key_bytes
        .try_into()
        .map_err(|_| anyhow!("peer encryption public key length is incorrect!"))?;

    let private_key = StaticSecret::from(private_key_arr);
    let public_key = PublicKey::from(peer_public_key_arr);

    let general_key = private_key.diffie_hellman(&public_key);
    Ok(general_key.to_bytes())
}

pub async fn load_or_create(pool: &SqlitePool) -> Result<Account> {
    if let Some(line) = sqlx::query_as::<_, (String, String, String, String, String)>(
        "SELECT account_id, public_key, private_key, encryption_public_key, encryption_private_key FROM accounts LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    {
        return Ok(Account {
            account_id: line.0,
            public_key: line.1,
            private_key: line.2,
            encryption_public_key: line.3,
            encryption_private_key: line.4,
        });
    }
    let mut rng = rand::thread_rng();
    let secret_key = SigningKey::generate(&mut rng);
    let open_key: VerifyingKey = secret_key.verifying_key();

    let public_key_bytes = open_key.to_bytes();
    let private_key_bytes = secret_key.to_bytes();

    let encryption_private_key = StaticSecret::random_from_rng(OsRng);
    let encryption_public_key = PublicKey::from(&encryption_private_key);

    let encryption_private_key_bytes = encryption_private_key.to_bytes();
    let encryption_public_key_bytes = encryption_public_key.to_bytes();

    let account_id = get_account_id(&public_key_bytes);

    let public_key = STANDARD.encode(public_key_bytes);
    let private_key = STANDARD.encode(private_key_bytes);

    let encryption_public_key = STANDARD.encode(encryption_public_key_bytes);
    let encryption_private_key = STANDARD.encode(encryption_private_key_bytes);

    sqlx::query("INSERT INTO accounts (account_id, public_key, private_key, created_date, encryption_public_key, encryption_private_key) VALUES (?, ?, ?, ?, ?, ?)",).bind(&account_id).bind(&public_key).bind(&private_key).bind(Utc::now().to_rfc3339()).bind(&encryption_public_key).bind(&encryption_private_key).execute(pool).await?;

    return Ok(Account {
        account_id,
        public_key,
        private_key,
        encryption_public_key,
        encryption_private_key,
    });
}
