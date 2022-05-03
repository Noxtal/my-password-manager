use std::io;
use std::fs::OpenOptions;
use serde_json;
use serde_json::json;
use serde_json::Value;
use sha2::{Sha256, Digest};
use hex_literal::hex;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

fn merge(a: &mut Value, b: Value) {
    match (a, b) {
        (a @ &mut Value::Object(_), Value::Object(b)) => {
            let a = a.as_object_mut().unwrap();
            for (k, v) in b {
                merge(a.entry(k).or_insert(Value::Null), v);
            }
        }
        (a, b) => *a = b,
    }
}

fn main() {
  println!("Welcome to my password manager!");
  let path = ".passwords";
  let masterkey_hash = hex!("113459eb7bb31bddee85ade5230d6ad5d8b2fb52879e00a84ff6ae1067a210d3");

  println!("Please enter your master key:");
  let mut masterkey = String::new();
  io::stdin().read_line(&mut masterkey).unwrap();

  let mut hasher = Sha256::new();
  hasher.update(masterkey.trim().as_bytes());
  let key = hasher.finalize();

  let mut hasher = Sha256::new();
  hasher.update(format!("{:x}", key));
  let result = hasher.finalize();

  if result[..] != masterkey_hash[..] {
    println!("Wrong!");
    return;
  }

  let crypt = new_magic_crypt!(String::from_utf8_lossy(&key), 256);

  loop {
    println!("Choose one the following options:");
    println!("1: Add/Update a password");
    println!("2: Find a password");
    println!("3: Exit");
  
  
    let mut option = String::new();
    io::stdin().read_line(&mut option).unwrap();
    let option = match option.trim().parse() {
      Ok(n)=>n,
      Err(_)=>continue,
    };

    let file = OpenOptions::new()
    .create(true)
    .write(true)
    .read(true)
    .open(path)
    .unwrap();
    
    let mut json: serde_json::Value = serde_json::from_reader(&file).unwrap_or(json!({}));
    
    match option {
      1 => {
        println!("Service: ");
        let mut service = String::new();
        io::stdin().read_line(&mut service).unwrap();

        println!("Password: ");
        let mut password = String::new();
        io::stdin().read_line(&mut password).unwrap();

        merge(&mut json, json!({
          service.trim(): crypt.encrypt_str_to_base64(password.trim())
        }));

        let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
        serde_json::to_writer_pretty(&file, &json).unwrap();
      },
      2 => {
        println!("Please enter the service:");
        let mut service = String::new();
        io::stdin().read_line(&mut service).unwrap();
        match json.get(&service.trim()) {
          Some(n) => println!("\nYour password for {} is {}", service,
          crypt.decrypt_base64_to_string(n.to_string().trim_matches('"')).unwrap()),
          None => eprintln!("\nCould not resolve service {}", service)
        }
      },
      3 => {
        println!("Goodbye!");
        break;
      },
      _ => continue,
    }
  }
}

// TODO masterkey for AES encryption (crate?)