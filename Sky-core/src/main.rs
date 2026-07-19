mod chats;
mod contacts;
mod identity;
mod invites;
mod messages;
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

    let checker = invites::verify_invite_token(&token)?;
    println!("\nSelf token verified:");
    println!("{:?}", checker);

    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 2 {
        let token = &args[1];
        let contact = contacts::add_contact(&pool, &account, token, None).await?;

        let chat = chats::get_chat(&pool, &account, &contact).await?;

        println!("\nContact added:");
        println!("contact_id: {}", contact.contact_id);
        println!("peer_account_id: {}", contact.peer_account_id);
        println!("trust_state: {}", contact.trusted);

        println!("\nChat ready:");
        println!("chat_id: {}", chat.chat_id);
        println!("peer_account_id: {}", chat.peer_account_id);
    }

    let contacts = contacts::list_contacts(&pool, &account).await?;
    let chats = chats::list_chats(&pool, &account).await?;

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

    println!("\nChats:");
    if chats.is_empty() {
        println!("No chats yet");
    } else {
        for chat in chats {
            println!(
                "- chat_id: {} | peer: {} | last_message: {}",
                chat.chat_id,
                chat.peer_account_id,
                chat.last_message_date.unwrap_or_else(|| "none".to_string())
            );
        }
    }

    Ok(())
}
