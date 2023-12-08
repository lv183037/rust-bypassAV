use std::{
    env,
    fs::{self, File},
    io::{BufReader, Read},
    process::Command,
};

use build::setupcargo;
use rand::Rng;
use sha2::{Digest, Sha256};

fn main() {
    let mut rng = rand::thread_rng();

    // 生成随机字符串
    let random_string: String = (0..6)
        .map(|_| rng.gen_range(b'A'..=b'Z') as char) // 生成大写字母
        .collect();

    // 打印随机字符串
    println!("Random String: {}", random_string);
    setupcargo(&random_string);
    buildfile(&random_string);
    cleanup(&random_string);
}

fn buildfile(project_name: &str) {
    // let project_name = "ma".to_string();
    let original_path = env::current_dir().unwrap();
    let project_path = original_path.join(project_name);
    env::set_current_dir(&project_path).expect("Failed to change directory to Rust project");
    let args = if cfg!(target_os = "windows") {
        vec!["build", "--release"]
    } else {
        vec!["build", "--release", "--target", "x86_64-pc-windows-gnu"]
    };

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

    let mut file = File::open(target_file).expect("Failed to open file");
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
