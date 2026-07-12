mod contacts;
mod identity;
mod invites;
mod storage;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let pool = storage::connect().await?;

    let account = identity::load_or_create(&pool).await?;
    let token = invites::token_generator(&account)?;

    println!("ID: ");
    println!("{}", account.account_id);

    println!("\nToken: ");
    println!("{}", token);

    Ok(())
}
