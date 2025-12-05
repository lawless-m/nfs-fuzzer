//! NFS Fuzzer - Main entry point

use clap::Parser;
use std::net::SocketAddr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod xdr;
mod rpc;

/// NFS Protocol Fuzzer
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target NFS server IP address
    #[arg(short, long)]
    target: String,

    /// Target port (default: 2049 for NFS)
    #[arg(short, long, default_value_t = 2049)]
    port: u16,

    /// NFS version to fuzz (3 or 4)
    #[arg(short = 'V', long, default_value_t = 3)]
    nfs_version: u32,

    /// Just test connectivity, don't fuzz
    #[arg(long)]
    test_connection: bool,

    /// Output directory for results
    #[arg(short, long, default_value = "./fuzz-results")]
    output: String,

    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Set up logging
    let level = match args.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };
    
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let target: SocketAddr = format!("{}:{}", args.target, args.port).parse()?;
    
    info!("NFS Fuzzer starting");
    info!("Target: {}", target);
    info!("NFS Version: {}", args.nfs_version);

    if args.test_connection {
        info!("Testing connection with NULL procedure...");
        // TODO: Send NULL RPC and check response
        let msg = rpc::simple_rpc_call(rpc::program::NFS, args.nfs_version, 0);
        info!("Would send {} bytes: {}", msg.len(), hex::encode(&msg));
    } else {
        info!("Fuzzing not yet implemented - this is a skeleton!");
        // TODO: Implement fuzzing loop
    }

    Ok(())
}
