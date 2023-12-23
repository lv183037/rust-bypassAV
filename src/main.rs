#![allow(warnings)]
use std::{
    collections::hash_map::RandomState,
    env,
    fs::{self, File},
    io::{BufReader, Read},
    process::Command,
    time::Instant,
};

use build::setupcargo;
use rand::{random, Rng};
use sha2::{digest::generic_array::sequence::GenericSequence, Digest, Sha256};

fn main() {
    let start_time = Instant::now();
    let random_string = generate_name();
    setupcargo(&random_string);
    buildfile(&random_string);
    cleanup(&random_string);
    let end_time = Instant::now();
    let elapsed_time = end_time - start_time;
    println!("[*] Use time: {}", elapsed_time.as_secs());
}

fn generate_name() -> String {
    let mut rng = rand::thread_rng();
    let random_string: String = (0..6).map(|_| rng.gen_range(b'A'..=b'Z') as char).collect();
    println!("[*] Random name: {}", &random_string);
    random_string
}

fn buildfile(project_name: &str) {
    println!("[*] Compiling project: {}", project_name);
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    env::set_current_dir(&project_path).expect("Failed to change directory to Rust project");
    let mut args = if cfg!(target_os = "windows") {
        vec!["build", "--release"]
    } else {
        vec!["build", "--release", "--target", "x86_64-pc-windows-gnu"]
    };
    args.push("--quiet");

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("Failed to execute 'cargo build'");

    if !status.success() {
        eprintln!("Error: 'cargo build' failed");
        std::process::exit(1);
    }
    env::set_current_dir(&original_path).expect("Failed to change directory back to original path");
}

pub fn cleanup(project_name: &str) {
    let file_name = project_name.to_owned() + ".exe";
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    let compiled_file = if cfg!(target_os = "windows") {
        project_path
            .join("target")
            .join("release")
            .join(format!("{}", file_name))
    } else {
        project_path
            .join("target")
            .join("x86_64-pc-windows-gnu")
            .join("release")
            .join(format!("{}", file_name))
    };
    if !compiled_file.exists() {
        println!("{:?}", compiled_file);
        eprintln!("Error: Compiled file not found");
        std::process::exit(1);
    }

    let target_file = original_path.join(format!("{}", file_name));
    println!("[*] {} Compiled", file_name);

    fs::copy(compiled_file, &target_file).expect("Failed to copy compiled file");
    fs::remove_dir_all(project_path).expect("Failed to remove Rust project folder");

    let file = File::open(target_file).expect("Failed to open file");
    let mut buf_reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let bytes_read = buf_reader.read(&mut buffer).expect("Failed to read file");
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let result = hasher.finalize();
    println!("[*] SHA-256 hash: {:x}", result);
}
