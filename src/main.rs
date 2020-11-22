extern crate crypto;

use get_if_addrs::get_if_addrs;
use reqwest::Client;

use serde::{Deserialize, Serialize};
use std::{thread, time, env};
use std::time::{Duration, SystemTime};
use std::path::Path;
use std::io;
use std::io::BufReader;
use std::fs::File;

use sha2::{Sha256};
use hmac::{Hmac, Mac, NewMac};
type HmacSha256 = Hmac<Sha256>;
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::seq::SliceRandom;
use crypto::digest::Digest;

type AesCbc = Cbc<Aes256, Pkcs7>;

#[derive(Deserialize, Clone)]
struct Config {
    // nextdest server URL
    // e.g http://[233::233]:233
    server: String,
    // device name
    name: String,
    // shared secret
    secret: String,
    // timeout (in seconds)
    // 0: will block on request
    timeout: u32,
    // negative value: will always try to communicate with server
    // 0: once timeout, program exits
    // other positive value: will try to communicate with server until reaches max retry times
    max_retry: i32,
    // interval of checking public IPv6 address
    // 0: only do once
    check_interval: u64,
    // API endpoint
    register_endpoint: String
}

#[derive(Serialize, Deserialize)]
struct RegisterV6 {
    name: String,
    hmac: String,
    addr: String,
    time: String,
}

#[derive(Serialize, Deserialize)]
struct RegisterV6Resp {
    #[serde(rename(deserialize = "dns_name"))]
    name: String,
    #[serde(rename(deserialize = "dns_addr"))]
    addr: String,
    direct_addr: String,
    success: bool,
    errors: String,
}

fn load_config<P>(path: P) -> io::Result<Config> where P: AsRef<Path> {
    // Open the file in read-only mode with buffer.
    let reader = BufReader::new(File::open(path)?);
    let config= serde_json::from_reader(reader)?;
    Ok(config)
}

const BASE_STR: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn gen_ascii_chars(size: usize) -> String {
    let mut rng = &mut rand::thread_rng();
    String::from_utf8(
        BASE_STR.as_bytes()
            .choose_multiple(&mut rng, size)
            .cloned()
            .collect()
    ).unwrap()
}

fn sha256(key: &str) -> Vec<u8> {
    let mut hasher = crypto::sha2::Sha256::new();
    hasher.input_str(key);
    let mut bytes = [0u8; 32];
    hasher.result(&mut bytes);
    bytes.to_vec()
}

fn encrypt(key: &str, data: &str) -> String {
    let iv_str = gen_ascii_chars(16);
    let iv = iv_str.as_bytes();
    let key = sha256(key);
    let cipher = AesCbc::new_var(&key, iv).unwrap();
    let ciphertext = cipher.encrypt_vec(data.as_bytes());
    let mut buffer = bytebuffer::ByteBuffer::from_bytes(iv);
    buffer.write_bytes(&ciphertext);
    let bytes = buffer.to_bytes();
    base64::encode(&bytes)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut config_path = "config.json".to_owned();
    if args.len() == 2 {
        config_path = args[1].clone();
    }

    let mut previous_v6_addr = "".to_owned();
    loop {
        let config = load_config(&config_path)?;
        let mut max_retry = config.max_retry;
        let (mut has_public_v6, is_timeout, mut ifs_v6) = check_public_v6(&config.server);
        if is_timeout {
            println!("[WARNING] timeout when query public IPv6, will try again");
            loop {
                if max_retry <= 0 {
                    eprintln!("[WARNING] mex retry times reached, will wait for next iteration");
                    break
                } else {
                    max_retry -= 1;
                    let (has_public_v6_retry, is_timeout_retry, ifs_v6_retry) = check_public_v6(&config.server);
                    if !is_timeout_retry {
                        has_public_v6 = has_public_v6_retry;
                        ifs_v6 = ifs_v6_retry;
                        break
                    }
                }
            }
        }

        for iface in &ifs_v6 {
            println!("[OK] Found public IPv6 address on {} => {:#?}", iface.name, iface.ip().to_string());
        }

        if has_public_v6 {
            let latest_v6_addr = ifs_v6[0].ip().to_string();
            if previous_v6_addr != latest_v6_addr {
                println!("[INFO] Detected IPv6 address changed from {} to {}", previous_v6_addr, latest_v6_addr);
                match register_public_v6(&config, &ifs_v6[0].ip().to_string()) {
                    Err(e) => eprintln!("[ERROR] {}", e.to_string()),
                    Ok(Some(resp)) => {
                        println!("[OK] DNS: {} => {}, Direct => {}", resp.name, resp.addr, resp.direct_addr);
                        previous_v6_addr = latest_v6_addr;
                    },
                    Ok(None) => (),
                };
            } else {
                println!("[INFO] IPv6 address {} is the same as previous one, will enter sleep", previous_v6_addr);
            }
        }

        if config.check_interval == 0 {
            break
        }
        let wait_interval = time::Duration::from_secs(config.check_interval);
        thread::sleep(wait_interval);
    }

    Ok(())
}

fn sign_and_encrypt(registration: &mut RegisterV6) -> serde_json::Result<String> {
    registration.time = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => format!("{}", n.as_secs()),
        Err(_) => panic!("[ERROR] SystemTime before UNIX EPOCH!")
    };

    // sign
    let json_string = serde_json::to_string(&registration)?;
    let secret = registration.hmac.clone();
    let mut mac = HmacSha256::new_varkey(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(json_string.as_bytes());
    let result = mac.finalize();
    registration.hmac = hex::encode(result.into_bytes());
    let json_string = serde_json::to_string(&registration)?;

    // encrypt
    let base64 = encrypt(&secret, &json_string);
    Ok(base64)
}

fn register_public_v6(config: &Config, v6: &String) -> serde_json::Result<Option<RegisterV6Resp>> {
    let mut register_api = config.server.clone();
    register_api.push_str(&config.register_endpoint);

    let mut registration = RegisterV6 {
        name: config.name.clone(),
        hmac: config.secret.clone(),
        addr: v6.clone(),
        time: "".to_owned()
    };
    let base64 = sign_and_encrypt(&mut registration)?;

    let client = Client::new();
    let resp = client.post(&register_api).body(base64).send();
    let server_resp = match resp {
        Ok(mut resp) => {
            match resp.text() {
                Ok(server_resp) => server_resp,
                Err(e) => {
                    eprintln!("[ERROR] {:#?}", e.to_string());
                    return Ok(None)
                }
            }
        },
        Err(e) => {
            eprintln!("[ERROR] {:#?}", e.to_string());
            return Ok(None)
        }
    };

    let resp: RegisterV6Resp = serde_json::from_str(&server_resp)?;
    if resp.addr != v6.to_string() {
        eprintln!("[ERROR] Server returned addr '{}' doesn't match requested addr '{}'", resp.addr, v6);
        return Ok(None)
    }
    if !resp.success {
        eprintln!("[ERROR] Server reported error: {}", resp.errors);
        return Ok(None)
    }
    Ok(Some(resp))
}

fn check_public_v6(server: &String) -> (bool, bool, Vec<get_if_addrs::Interface>) {
    let client = match reqwest::Client::builder()
        .gzip(true)
        .timeout(Duration::from_secs(10))
        .build() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("[ERROR] {}", e.to_string());
            return (false, false, vec![])
        }
    };
    let resp = client.get(server).send();
    let v6 = match resp {
        Ok(mut resp) => {
            match resp.text() {
                Ok(v6) => v6,
                Err(e) => {
                    eprintln!("[ERROR] {}", e.to_string());
                    return (false, false, vec![])
                }
            }
        },
        Err(e) => {
            eprintln!("[ERROR] {:#?}", e.to_string());
            return if e.is_timeout() {
                (false, true, vec![])
            } else {
                (false, false, vec![])
            }
        }
    };

    let ifs = get_if_addrs().expect("Cannot get interface info, no permission?");
    let ifs_v6 = ifs.into_iter().filter(|iface| {
        match (iface.is_loopback(), &iface.addr) {
            (false, get_if_addrs::IfAddr::V6(_)) => {
                true
            },
            (_, _) => false
        }
    }).filter_map(|iface| {
        if iface.ip().to_string().trim() == v6.trim() {
            Some(iface)
        } else {
            None
        }
    }).collect::<Vec<_>>();

    (ifs_v6.len() > 0, false, ifs_v6)
}
