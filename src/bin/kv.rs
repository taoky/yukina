use clap::{Parser, Subcommand};
use std::path::PathBuf;
use yukina::SizeDBItem;

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Get(Args),
    Remove(Args),
    Scan(ScanArgs),
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    db: PathBuf,

    #[clap(value_parser)]
    key: String,
}

#[derive(Parser, Debug)]
struct ScanArgs {
    #[clap(long)]
    db: PathBuf,

    #[clap(value_parser)]
    scan_prefix: String,
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Get(args) => {
            let db = sled::open(args.db).unwrap();
            let value = db.get(&args.key).unwrap();
            if let Some(value) = value {
                println!("{:?}", bincode::deserialize::<SizeDBItem>(&value).unwrap());
            } else {
                println!("Key not found");
            }
        }
        Commands::Remove(args) => {
            let db = sled::open(args.db).unwrap();
            db.remove(&args.key).unwrap();
        }
        Commands::Scan(args) => {
            let db = sled::open(args.db).unwrap();
            let scan_prefix = args.scan_prefix;
            let mut iter = db.scan_prefix(scan_prefix.as_bytes());
            while let Some(Ok((key, value))) = iter.next() {
                println!(
                    "{} {:?}",
                    std::str::from_utf8(&key).unwrap(),
                    bincode::deserialize::<SizeDBItem>(&value).unwrap()
                );
            }
        }
    }
}
