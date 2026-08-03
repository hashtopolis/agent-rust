use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "htp-agent", version, about)]
struct Cli {}

#[tokio::main]
async fn main() {
    let _cli = Cli::parse();

    tracing_subscriber::fmt().init();

    todo!("wire up config -> client -> agent");
}
