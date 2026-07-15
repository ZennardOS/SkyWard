mod contacts;
mod identity;
mod invites;
mod storage;
mod chats;

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

    let checker = invites::verify_invite_token(&token)?;
    println!("\nSelf token verified:");
    println!("{:?}", checker);

    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 2 {
        let token = &args[1];
        let contact = contacts::add_contact(&pool, &account, token, None).await?;

        println!("\nContact added:");
        println!("contact_id: {}", contact.contact_id);
        println!("peer_account_id: {}", contact.peer_account_id);
        println!("trust_state: {}", contact.trusted);
    }

    let contacts = contacts::list_contacts(&pool, &account).await?;
    println!("\nContacts:");
    if contacts.is_empty() {
        println!("No contacts yet");
    } else {
        for contact in contacts {
            println!(
                "- {} | nickname: {} | trust: {}",
                contact.peer_account_id,
                contact.nickname.unwrap_or_else(|| "none".to_string()),
                contact.trusted
            );
        }
    }

    Ok(())
}
