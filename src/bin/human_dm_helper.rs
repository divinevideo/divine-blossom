//! Test helper binary that simulates a human Nostr client.
//!
//! Used in e2e tests to send and receive NIP-17 DMs through a relay,
//! verifying the daemon's human session handling.
//!
//! Usage:
//!   human-dm-helper send <relay_url> <daemon_npub> <message> [--nsec <nsec>]
//!   human-dm-helper recv <relay_url> [--nsec <nsec>] [--timeout <secs>]
//!   human-dm-helper keygen

use nostr_sdk::prelude::*;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  human-dm-helper keygen");
        eprintln!("  human-dm-helper send <relay_url> <daemon_npub> <message> [--nsec <nsec>]");
        eprintln!("  human-dm-helper recv <relay_url> [--nsec <nsec>] [--timeout <secs>]");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "keygen" => {
            let keys = Keys::generate();
            let npub = keys.public_key().to_bech32()?;
            let nsec = keys.secret_key().to_bech32()?;
            println!("{npub}");
            println!("{nsec}");
        }
        "send" => {
            if args.len() < 5 {
                eprintln!(
                    "Usage: human-dm-helper send <relay_url> <daemon_npub> <message> [--nsec <nsec>]"
                );
                std::process::exit(1);
            }
            let relay_url = &args[2];
            let daemon_npub = &args[3];
            let message = &args[4];
            let nsec = parse_flag(&args, "--nsec");

            let keys = match nsec {
                Some(s) => Keys::parse(&s)?,
                None => Keys::generate(),
            };

            let client = Client::builder().signer(keys.clone()).build();
            client.automatic_authentication(true);
            client.add_relay(relay_url.as_str()).await?;
            client.connect().await;

            // Wait for relay connection
            tokio::time::sleep(Duration::from_secs(2)).await;

            let target = PublicKey::from_bech32(daemon_npub)?;
            client
                .send_private_msg_to([relay_url.as_str()], target, message.to_string(), [])
                .await?;

            eprintln!("sent DM to {daemon_npub}");

            // Brief delay for relay to process
            tokio::time::sleep(Duration::from_millis(500)).await;
            client.disconnect().await;
        }
        "recv" => {
            if args.len() < 3 {
                eprintln!(
                    "Usage: human-dm-helper recv <relay_url> [--nsec <nsec>] [--timeout <secs>]"
                );
                std::process::exit(1);
            }
            let relay_url = &args[2];
            let nsec = parse_flag(&args, "--nsec");
            let timeout_secs: u64 = parse_flag(&args, "--timeout")
                .and_then(|s| s.parse().ok())
                .unwrap_or(15);

            let keys = match nsec {
                Some(s) => Keys::parse(&s)?,
                None => {
                    eprintln!("--nsec required for recv");
                    std::process::exit(1);
                }
            };

            let client = Client::builder().signer(keys.clone()).build();
            client.automatic_authentication(true);
            client.add_relay(relay_url.as_str()).await?;
            client.connect().await;

            // Wait for relay connection
            tokio::time::sleep(Duration::from_secs(2)).await;

            // Subscribe to gift-wrapped messages for us
            let filter = Filter::new()
                .pubkey(keys.public_key())
                .kind(Kind::GiftWrap)
                .limit(0);

            client.subscribe(filter, None).await?;

            let timeout = Duration::from_secs(timeout_secs);
            let recv_client = client.clone();
            let _ = tokio::time::timeout(timeout, async move {
                recv_client
                    .handle_notifications(|notification| {
                        let recv_client = recv_client.clone();
                        async move {
                            if let RelayPoolNotification::Event { event, .. } = notification
                                && event.kind == Kind::GiftWrap
                            {
                                match recv_client.unwrap_gift_wrap(&event).await {
                                    Ok(UnwrappedGift { rumor, sender }) => {
                                        let npub =
                                            sender.to_bech32().unwrap_or_else(|_| "unknown".into());
                                        println!("{npub}\t{}", rumor.content);
                                        return Ok(true); // stop after first message
                                    }
                                    Err(e) => {
                                        eprintln!("unwrap error: {e}");
                                    }
                                }
                            }
                            Ok(false)
                        }
                    })
                    .await
            })
            .await;

            client.disconnect().await;
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
