use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Get(Args),
    Remove(Args),
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    db: PathBuf,

    #[clap(value_parser)]
    key: String,
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Get(args) => {
            let db = sled::open(args.db).unwrap();
            let value = db.get(&args.key).unwrap();
            if let Some(value) = value {
                println!("{}", String::from_utf8(value.to_vec()).unwrap());
            } else {
                println!("Key not found");
            }
        }
        Commands::Remove(args) => {
            let db = sled::open(args.db).unwrap();
            db.remove(&args.key).unwrap();
        }
    }
}
