use clap::Args;

#[derive(Args)]
pub struct ServerArgs {
    /// Port to run the server on
    #[arg(short, long, default_value = "8080")]
    pub port: u16,

    /// Host to bind the server to
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,
}

pub fn run_server(args: ServerArgs) {
    println!("Starting server on {}:{}", args.host, args.port);
    // TODO: Implement server logic
}
