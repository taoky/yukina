use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use yukina::{db, db_get, LocalSizeDBItem, RemoteSizeDBItem};

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

#[derive(ValueEnum, Debug, Clone, Copy)]
enum Type {
    Remote,
    Local,
}

#[derive(Debug)]
#[allow(dead_code)] // Item is only used when printing with debug
enum TypeResult {
    Remote(RemoteSizeDBItem),
    Local(LocalSizeDBItem),
}

#[derive(Parser, Debug)]
struct Args {
    // TODO: shared argument for clap
    #[clap(long)]
    db: PathBuf,

    #[clap(long, value_enum, default_value = "remote")]
    r#type: Type,

    #[clap(value_parser)]
    key: String,
}

#[derive(Parser, Debug)]
struct ScanArgs {
    #[clap(long)]
    db: PathBuf,

    #[clap(long, value_enum)]
    r#type: Type,

    #[clap(value_parser)]
    scan_prefix: String,
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Get(args) => {
            let db = db::Db::open(args.db).unwrap();
            let value = match args.r#type {
                Type::Remote => {
                    TypeResult::Remote(db_get::<RemoteSizeDBItem>(Some(&db), &args.key).unwrap())
                }
                Type::Local => {
                    TypeResult::Local(db_get::<LocalSizeDBItem>(Some(&db), &args.key).unwrap())
                }
            };
            println!("{:?}", value);
        }
        Commands::Remove(args) => {
            let db = db::Db::open(args.db).unwrap();
            db.remove(&args.key).unwrap();
        }
        Commands::Scan(args) => {
            let db = db::Db::open(args.db).unwrap();
            let scan_prefix = args.scan_prefix;
            let mut iter = db.scan_prefix(&scan_prefix).unwrap();
            while let Some(Ok((key, value))) = iter.next() {
                let value = match args.r#type {
                    Type::Remote => TypeResult::Remote(
                        bincode::deserialize::<RemoteSizeDBItem>(&value).unwrap(),
                    ),
                    Type::Local => {
                        TypeResult::Local(bincode::deserialize::<LocalSizeDBItem>(&value).unwrap())
                    }
                };
                println!("{} {:?}", &key, value);
            }
        }
    }
}
