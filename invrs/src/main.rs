use clap::Parser;
use crate::tasks::docker::Docker;
use crate::tasks::workflows::Workflows;

pub mod env;
pub mod tasks;

#[derive(Parser)]
struct Cli {
    // The name of the task to execute
    task: String,

    // The command in the task to execute
    #[arg(default_value = "")]
    command: String,
}

fn main() {
    let args = Cli::parse();

    match args.task.as_str() {
        "list" | "ls" => {
            println!("invrs: supported tasks (and commands) are:");
            println!("- list (ls): list available tasks");
            println!("- docker:");
            println!("\t- build: build experiments artifcat docker image");
            println!("- workflows:");
            println!("\t- list: list available workflows");
        },
        "docker" => Docker::do_cmd(args.command),
        "workflows" => Workflows::do_cmd(args.command),
        _ => panic!("invrs: unrecognised task: {0}", args.task)
    }
}
