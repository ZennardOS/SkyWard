mod chats;
mod contacts;
mod cover;
mod identity;
mod invites;
mod messages;
mod storage;

use anyhow::Result;

use crate::cover::encode_cover_message;

fn helper() {
    println!(
        r#"
Sky Core CLI

Usage:
  cargo run -- me
  cargo run -- token
  cargo run -- verify-token <invite_token>
  cargo run -- add <invite_token>
  cargo run -- contacts
  cargo run -- chats
  cargo run -- send <chat_id> <message>
  cargo run -- history <chat_id>

Commands:
  me             Show current local account
  token          Generate invite token
  verify-token   Verify an invite token
  add            Add contact by invite token and create chat
  contacts       List contacts
  chats          List chats
  send           Save outgoing local message
  history        Show messages for chat
"#
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let pool = storage::connect().await?;
    let account = identity::load_or_create(&pool).await?;

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        helper();
        return Ok(());
    }

    match args[1].as_str() {
        "me" => {
            println!("Account id: {}", account.account_id);
            println!("Public key: {}", account.public_key);
        }
        "token" => {
            let token = invites::token_generator(&account)?;
            println!("Invite token: {}", token);
        }
        "verify" => {
            if args.len() < 3 {
                println!("Usage: cargo run -- verify-token <invite_token>");
                return Ok(());
            }

            let token = &args[2];
            let payload = invites::verify_invite_token(token)?;

            println!("Token is valid: {:?}", payload);
        }
        "add" => {
            if args.len() < 3 {
                println!("Usage: cargo run -- add <invite_token>");
                return Ok(());
            }

            let token = &args[2];

            let contact = contacts::add_contact(&pool, &account, token, None).await?;
            let chat = chats::get_chat(&pool, &account, &contact).await?;

            println!("Contact added:");
            println!("contact_id: {}", contact.contact_id);
            println!("peer_account_id: {}", contact.peer_account_id);
            println!("trust_state: {}", contact.trusted);

            println!("\nChat ready:");
            println!("chat_id: {}", chat.chat_id);
            println!("peer_account_id: {}", chat.peer_account_id);
        }
        "contacts" => {
            let contacts = contacts::list_contacts(&pool, &account).await?;
            if contacts.is_empty() {
                println!("No contacts yet");
            } else {
                println!("Contacts: ");
                for contact in contacts {
                    println!(
                        "- {} | nickname: {} | trust: {}",
                        contact.peer_account_id,
                        contact.nickname.unwrap_or_else(|| "none".to_string()),
                        contact.trusted
                    );
                }
            }
        }
        "chats" => {
            let chats = chats::list_chats(&pool, &account).await?;

            if chats.is_empty() {
                println!("No chats yet");
            } else {
                println!("Chats: ");
                for chat in chats {
                    println!(
                        "- chat_id: {} | peer: {} | last_message: {}",
                        chat.chat_id,
                        chat.peer_account_id,
                        chat.last_message_date.unwrap_or_else(|| "none".to_string())
                    );
                }
            }
        }
        "send" => {
            if args.len() < 4 {
                println!("Usage: cargo run -- send <chat_id> <message>");
                return Ok(());
            }
            let chat_id = &args[2];
            let plaintext = args[3..].join(" ");

            let chat = chats::get_chat_by_id(&pool, &account, chat_id).await?;

            let messages =
                messages::outgoing_message_saver(&pool, &account, &chat, &plaintext).await?;

            println!("Message was saved: ");
            println!("message id: {}", messages.message_id);
            println!("chat id: {}", messages.chat_id);
            println!("body: {}", messages.body);
            println!("state: {}", messages.delivery_state);
        }

        "pack" => {
            if args.len() < 4 {
                println!("Usage: cargo run -- send <chat_id> <message>");
                return Ok(());
            }

            let chat_id = &args[2];
            let plaintext = args[3..].join(" ");

            let chat = chats::get_chat_by_id(&pool, &account, chat_id).await?;
            let message =
                messages::outgoing_message_saver(&pool, &account, &chat, &plaintext).await?;

            let cover_message = cover::get_cover_message(&message);
            let signed = cover::sign_cover(&cover_message, &account)?;

            println!("Signed cover: {:?}", signed);

            let verified = cover::verify_signed_cover(&pool, &signed, &account).await?;

            println!("Verified: {:?}", verified);

            let encoded = encode_cover_message(&cover_message)?;

            println!("Covered: {}", encoded);

            let decoded = cover::decode_cover_message(&encoded)?;

            println!("decoded: {:?}", decoded);
        }

        "history" => {
            if args.len() < 3 {
                println!("Usage: cargo run -- history <chat_id>");
                return Ok(());
            }

            let chat_id = &args[2];

            let messages = messages::list_messages(&pool, &account, chat_id).await?;

            println!("Messages: ");

            if messages.is_empty() {
                println!("No messages yet!");
            } else {
                for message in messages {
                    println!(
                        "[{}] {}: {} ({})",
                        message.created_date,
                        message.direction,
                        message.body,
                        message.delivery_state
                    );
                }
            }
        }

        _ => {
            println!("Unknown command: {}", args[1]);
            helper();
        }
    }

    Ok(())
    // if args.len() >= 2 {
    //     match args[1].as_str() {
    //         "add" => {
    //             let token = &args[2];
    //             let contact = contacts::add_contact(&pool, &account, token, None).await?;

    //             let chat = chats::get_chat(&pool, &account, &contact).await?;

    //             println!("\nContact added:");
    //             println!("contact_id: {}", contact.contact_id);
    //             println!("peer_account_id: {}", contact.peer_account_id);
    //             println!("trust_state: {}", contact.trusted);

    //             println!("\nChat ready:");
    //             println!("chat_id: {}", chat.chat_id);
    //             println!("peer_account_id: {}", chat.peer_account_id);
    //         }

    //         "send" => {
    //             let chat_id = &args[2];
    //             let plaintext = args[3..].join(" ");

    //             let chat = chats::get_chat_by_id(&pool, &account, chat_id).await?;

    //             let messages =
    //                 messages::outgoing_message_saver(&pool, &account, &chat, &plaintext).await?;

    //             println!("Message was saved: ");
    //             println!("message id: {}", messages.message_id);
    //             println!("chat id: {}", messages.chat_id);
    //             println!("body: {}", messages.body);
    //             println!("state: {}", messages.delivery_state);
    //         }

    //         "history" => {
    //             let chat_id = &args[2];

    //             let messages = messages::list_messages(&pool, &account, chat_id).await?;

    //             println!("Messages: ");

    //             if messages.is_empty() {
    //                 println!("No messages yet!");
    //             } else {
    //                 for message in messages {
    //                     println!(
    //                         "[{}] {}: {} ({})",
    //                         message.created_date,
    //                         message.direction,
    //                         message.body,
    //                         message.delivery_state
    //                     );
    //                 }
    //             }
    //         }

    //         _ => {
    //             println!("Unknown...");
    //         }
    //     }
    // }

    // let contacts = contacts::list_contacts(&pool, &account).await?;
    // let chats = chats::list_chats(&pool, &account).await?;

    // println!("\nContacts:");
    // if contacts.is_empty() {
    //     println!("No contacts yet");
    // } else {
    //     for contact in contacts {
    //         println!(
    //             "- {} | nickname: {} | trust: {}",
    //             contact.peer_account_id,
    //             contact.nickname.unwrap_or_else(|| "none".to_string()),
    //             contact.trusted
    //         );
    //     }
    // }

    // println!("\nChats:");
    // if chats.is_empty() {
    //     println!("No chats yet");
    // } else {
    //     for chat in chats {
    //         println!(
    //             "- chat_id: {} | peer: {} | last_message: {}",
    //             chat.chat_id,
    //             chat.peer_account_id,
    //             chat.last_message_date.unwrap_or_else(|| "none".to_string())
    //         );
    //     }
    // }

    // Ok(())
    //
}
