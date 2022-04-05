//! Anoma Wallet CLI.

use std::fs::File;
use std::io::{self, Write};

use anoma::types::key::*;
use anoma_apps::cli;
use anoma_apps::cli::{args, cmds, Context};
use anoma_apps::wallet::DecryptionError;
use borsh::BorshSerialize;
use color_eyre::eyre::Result;
use itertools::sorted;
use rand_core::OsRng;
use masp_primitives::keys::FullViewingKey;
use masp_primitives::zip32::ExtendedSpendingKey;
use anoma_apps::client::tx::find_valid_diversifier;
use anoma::types::masp::MaspValue;

pub fn main() -> Result<()> {
    let (cmd, ctx) = cli::anoma_wallet_cli();
    match cmd {
        cmds::AnomaWallet::Key(sub) => match sub {
            cmds::WalletKey::Gen(cmds::KeyGen(args)) => {
                key_and_address_gen(ctx, args)
            }
            cmds::WalletKey::Find(cmds::KeyFind(args)) => key_find(ctx, args),
            cmds::WalletKey::List(cmds::KeyList(args)) => key_list(ctx, args),
            cmds::WalletKey::Export(cmds::Export(args)) => {
                key_export(ctx, args)
            }
        },
        cmds::AnomaWallet::Address(sub) => match sub {
            cmds::WalletAddress::Gen(cmds::AddressGen(args)) => {
                key_and_address_gen(ctx, args)
            }
            cmds::WalletAddress::Find(cmds::AddressFind(args)) => {
                address_find(ctx, args)
            }
            cmds::WalletAddress::List(cmds::AddressList) => address_list(ctx),
            cmds::WalletAddress::Add(cmds::AddressAdd(args)) => {
                address_add(ctx, args)
            }
        },
        cmds::AnomaWallet::Masp(sub) => match sub {
            cmds::WalletMasp::GenSpendKey(cmds::MaspGenSpendKey(args)) => {
                spending_key_gen(ctx, args);
            }
            cmds::WalletMasp::GenPayAddr(cmds::MaspGenPayAddr(args)) => {
                payment_address_gen(ctx, args)
            }
            cmds::WalletMasp::DeriveViewKey(cmds::MaspDeriveViewKey(args)) => {
                viewing_key_derive(ctx, args)
            }
            cmds::WalletMasp::AddAddrKey(cmds::MaspAddAddrKey(args)) => {
                address_key_add(ctx, args)
            }
            cmds::WalletMasp::ListPayAddrs(cmds::MaspListPayAddrs) => {
                payment_addresses_list(ctx)
            }
            cmds::WalletMasp::ListViewKeys(cmds::MaspListViewKeys) => {
                viewing_keys_list(ctx)
            }
            cmds::WalletMasp::ListSpendKeys(cmds::MaspListSpendKeys(args)) => {
                spending_keys_list(ctx, args)
            }
        }
    }
    Ok(())
}

/// List spending keys.
fn spending_keys_list(
    ctx: Context,
    args::SpendKeysList {
        unsafe_show_secret,
    }: args::SpendKeysList,
) {
    let wallet = ctx.wallet;
    let known_keys = wallet.get_spending_keys();
    if known_keys.is_empty() {
        println!(
            "No known spending keys. Try `masp add --alias my-addr --value ...` to \
             add a new spending key to the wallet."
        );
    } else {
        let stdout = io::stdout();
        let mut w = stdout.lock();
        writeln!(w, "Known spending keys:").unwrap();
        for (alias, key) in known_keys {
            write!(w, "  \"{}\"", alias).unwrap();
            if unsafe_show_secret {
                writeln!(w, ": {}", key)
            } else {
                writeln!(w, "")
            }.unwrap();
        }
    }
}

/// List viewing keys.
fn viewing_keys_list(
    ctx: Context,
) {
    let wallet = ctx.wallet;
    let known_keys = wallet.get_viewing_keys();
    if known_keys.is_empty() {
        println!(
            "No known viewing keys. Try `masp add --alias my-addr --value ...` to \
             add a new viewing key to the wallet."
        );
    } else {
        let stdout = io::stdout();
        let mut w = stdout.lock();
        writeln!(w, "Known viewing keys:").unwrap();
        for (alias, key) in known_keys {
            writeln!(w, "  \"{}\": {}", alias, key)
                .unwrap();
        }
    }
}

/// List payment addresses.
fn payment_addresses_list(
    ctx: Context,
) {
    let wallet = ctx.wallet;
    let known_addresses = wallet.get_payment_addrs();
    if known_addresses.is_empty() {
        println!(
            "No known payment addresses. Try `masp gen-payment-addr --alias my-addr` to \
             generate a new payment address."
        );
    } else {
        let stdout = io::stdout();
        let mut w = stdout.lock();
        writeln!(w, "Known payment addresses:").unwrap();
        for (alias, address) in sorted(known_addresses) {
            writeln!(w, "  \"{}\": {}", alias, address)
                .unwrap();
        }
    }
}

/// Generate a spending key.
fn spending_key_gen(
    ctx: Context,
    args::MaspSpendKeyGen {
        alias,
    }: args::MaspSpendKeyGen,
) {
    let mut wallet = ctx.wallet;
    let (alias, _key) = wallet.gen_spending_key(alias);
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    println!(
        "Successfully added a spending key with alias: \"{}\"",
        alias
    );
}

/// Generate a shielded payment address from the given key.
fn payment_address_gen(
    mut ctx: Context,
    args::MaspPayAddrGen {
        alias,
        viewing_key,
    }: args::MaspPayAddrGen,
) {
    let viewing_key = FullViewingKey::from(ctx.get_cached(&viewing_key)).vk;
    let (div, _g_d) = find_valid_diversifier(&mut OsRng);
    let payment_addr = viewing_key.to_payment_address(div).expect("a PaymentAddress");
    let mut wallet = ctx.wallet;
    let alias = wallet.insert_payment_addr(alias, payment_addr.into()).unwrap_or_else(|| {
        eprintln!("Payment address not added");
        cli::safe_exit(1);
    });
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    println!(
        "Successfully generated a payment address with the following alias: {}",
        alias,
    );
}

/// Derive a full viewing key from the given spending key.
fn viewing_key_derive(
    mut ctx: Context,
    args::MaspViewKeyDerive {
        alias,
        spending_key,
    }: args::MaspViewKeyDerive,
) {
    let fvk = FullViewingKey::from_expanded_spending_key(
        &ExtendedSpendingKey::from(ctx.get_cached(&spending_key))
            .expsk.into(),
    );
    let mut wallet = ctx.wallet;
    let alias = wallet.insert_viewing_key(alias, fvk.into()).unwrap_or_else(|| {
        eprintln!("Viewing key not added");
        cli::safe_exit(1);
    });
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    println!(
        "Successfully derived a viewing key with the following alias: {}",
        alias,
    );
}

/// Add a viewing key, spending key, or payment address to wallet.
fn address_key_add(
    mut ctx: Context,
    args::MaspAddrKeyAdd {
        alias,
        value,
    }: args::MaspAddrKeyAdd,
) {
    let (alias, typ) = match value {
        MaspValue::FullViewingKey(viewing_key) => {
            let alias = ctx
                .wallet
                .insert_viewing_key(alias, viewing_key)
                .unwrap_or_else(|| {
                    eprintln!("Viewing key not added");
                    cli::safe_exit(1);
                });
            (alias, "viewing key")
        },
        MaspValue::ExtendedSpendingKey(spending_key) => {
            let alias = ctx
                .wallet
                .insert_spending_key(alias, spending_key)
                .unwrap_or_else(|| {
                    eprintln!("Spending key not added");
                    cli::safe_exit(1);
                });
            (alias, "spending key")
        },
        MaspValue::PaymentAddress(payment_addr) => {
            let alias = ctx
                .wallet
                .insert_payment_addr(alias, payment_addr)
                .unwrap_or_else(|| {
                    eprintln!("Payment address not added");
                    cli::safe_exit(1);
                });
            (alias, "payment address")
        },
    };
    ctx.wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    println!(
        "Successfully added a {} with the following alias to wallet: {}",
        typ,
        alias,
    );
}

/// Generate a new keypair and derive implicit address from it and store them in
/// the wallet.
fn key_and_address_gen(
    ctx: Context,
    args::KeyAndAddressGen {
        alias,
        unsafe_dont_encrypt,
    }: args::KeyAndAddressGen,
) {
    let mut wallet = ctx.wallet;
    let (alias, _key) = wallet.gen_key(alias, unsafe_dont_encrypt);
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    println!(
        "Successfully added a key and an address with alias: \"{}\"",
        alias
    );
}

/// Find a keypair in the wallet store.
fn key_find(
    ctx: Context,
    args::KeyFind {
        public_key,
        alias,
        value,
        unsafe_show_secret,
    }: args::KeyFind,
) {
    let mut wallet = ctx.wallet;
    let found_keypair = match public_key {
        Some(pk) => wallet.find_key_by_pk(&pk),
        None => {
            let alias = alias.or(value);
            match alias {
                None => {
                    eprintln!(
                        "An alias, public key or public key hash needs to be \
                         supplied"
                    );
                    cli::safe_exit(1)
                }
                Some(alias) => wallet.find_key(alias.to_lowercase()),
            }
        }
    };
    match found_keypair {
        Ok(keypair) => {
            let pkh: PublicKeyHash = (&keypair.ref_to()).into();
            println!("Public key hash: {}", pkh);
            println!("Public key: {}", keypair.ref_to());
            if unsafe_show_secret {
                println!("Secret key: {}", keypair);
            }
        }
        Err(err) => {
            eprintln!("{}", err);
        }
    }
}

/// List all known keys.
fn key_list(
    ctx: Context,
    args::KeyList {
        decrypt,
        unsafe_show_secret,
    }: args::KeyList,
) {
    let wallet = ctx.wallet;
    let known_keys = wallet.get_keys();
    if known_keys.is_empty() {
        println!(
            "No known keys. Try `key gen --alias my-key` to generate a new \
             key."
        );
    } else {
        let stdout = io::stdout();
        let mut w = stdout.lock();
        writeln!(w, "Known keys:").unwrap();
        for (alias, (stored_keypair, pkh)) in known_keys {
            let encrypted = if stored_keypair.is_encrypted() {
                "encrypted"
            } else {
                "not encrypted"
            };
            writeln!(w, "  Alias \"{}\" ({}):", alias, encrypted).unwrap();
            if let Some(pkh) = pkh {
                writeln!(w, "    Public key hash: {}", pkh).unwrap();
            }
            match stored_keypair.get(decrypt) {
                Ok(keypair) => {
                    writeln!(w, "    Public key: {}", keypair.ref_to())
                        .unwrap();
                    if unsafe_show_secret {
                        writeln!(w, "    Secret key: {}", keypair).unwrap();
                    }
                }
                Err(DecryptionError::NotDecrypting) if !decrypt => {
                    continue;
                }
                Err(err) => {
                    writeln!(w, "    Couldn't decrypt the keypair: {}", err)
                        .unwrap();
                }
            }
        }
    }
}

/// Export a keypair to a file.
fn key_export(ctx: Context, args::KeyExport { alias }: args::KeyExport) {
    let mut wallet = ctx.wallet;
    wallet
        .find_key(alias.to_lowercase())
        .map(|keypair| {
            let file_data = keypair
                .try_to_vec()
                .expect("Encoding keypair shouldn't fail");
            let file_name = format!("key_{}", alias.to_lowercase());
            let mut file = File::create(&file_name).unwrap();

            file.write_all(file_data.as_ref()).unwrap();
            println!("Exported to file {}", file_name);
        })
        .unwrap_or_else(|err| {
            eprintln!("{}", err);
            cli::safe_exit(1)
        })
}

/// List all known addresses.
fn address_list(ctx: Context) {
    let wallet = ctx.wallet;
    let known_addresses = wallet.get_addresses();
    if known_addresses.is_empty() {
        println!(
            "No known addresses. Try `address gen --alias my-addr` to \
             generate a new implicit address."
        );
    } else {
        let stdout = io::stdout();
        let mut w = stdout.lock();
        writeln!(w, "Known addresses:").unwrap();
        for (alias, address) in sorted(known_addresses) {
            writeln!(w, "  \"{}\": {}", alias, address.to_pretty_string())
                .unwrap();
        }
    }
}

/// Find address by its alias.
fn address_find(ctx: Context, args: args::AddressFind) {
    let wallet = ctx.wallet;
    if let Some(address) = wallet.find_address(&args.alias) {
        println!("Found address {}", address.to_pretty_string());
    } else {
        println!(
            "No address with alias {} found. Use the command `address list` \
             to see all the known addresses.",
            args.alias.to_lowercase()
        );
    }
}

/// Add an address to the wallet.
fn address_add(ctx: Context, args: args::AddressAdd) {
    let mut wallet = ctx.wallet;
    if wallet
        .add_address(args.alias.clone().to_lowercase(), args.address)
        .is_none()
    {
        eprintln!("Address not added");
        cli::safe_exit(1);
    }
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    println!(
        "Successfully added a key and an address with alias: \"{}\"",
        args.alias.to_lowercase()
    );
}
