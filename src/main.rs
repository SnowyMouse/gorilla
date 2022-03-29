extern crate clap;
use clap::Parser;

use std::fs::File;
use std::io::{Read, Write};

mod def_dumper;

fn main() {
    #[derive(Parser)]
    #[clap(version, about)]
    struct Args {
        exe_path: String,
        output_json: String
    }

    let args = Args::parse();
    let mut file_data = Vec::new();

    // Read the file
    match |exe_path: &str, file_data: &mut Vec<u8>| -> std::io::Result<usize> {
        File::open(exe_path)?.read_to_end(file_data)
    }(&args.exe_path, &mut file_data) {
        Err(n) => {
            eprintln!("Can't read {}: {}", args.exe_path, n);
            std::process::exit(1);
        },
        _ => ()
    };

    // Make the json
    let json = match def_dumper::dump_definitions_into_json(&file_data) {
        Some(n) => n,
        None => {
            eprintln!("Failed! The exe might not be correct.");
            std::process::exit(1);
        }
    };

    // Write the json
    match |json_path: &str| -> std::io::Result<()> {
        File::create(json_path)?.write_all(&json)
    }(&args.output_json) {
        Err(n) => {
            eprintln!("Can't write {}: {}", args.output_json, n);
            std::process::exit(1);
        },
        _ => ()
    }
}
