use std::env;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

mod client;
use client::Client;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Params {
    K {
        num_threshold: u16,
        num_parties: u16,
    },
    S {
        num_threshold: u16,
        active_parties: Vec<u16>,
        message: String,
    },
}

#[async_trait]
pub trait ThresholdSigning {
    async fn upload_keygen_params(&self, id: String, num_threshold: u16, num_parties: u16);

    async fn upload_sign_params(
        &self,
        id: String,
        num_threshold: u16,
        active_parties: Vec<u16>,
        message: String,
    );
}

#[async_trait]
impl ThresholdSigning for Client {
    async fn upload_keygen_params(&self, id: String, num_threshold: u16, num_parties: u16) {
        let params = Params::K {
            num_threshold,
            num_parties,
        };
        let json = serde_json::to_vec(&params).unwrap();
        let upload_val = vec![json; self.node_addrs.len()];
        self.upload_blob(id.clone() + ".json", upload_val).await;
    }

    async fn upload_sign_params(
        &self,
        id: String,
        num_threshold: u16,
        active_parties: Vec<u16>,
        message: String,
    ) {
        let params = Params::S {
            num_threshold,
            active_parties,
            message,
        };
        let json = serde_json::to_vec(&params).unwrap();
        let upload_val = vec![json; self.node_addrs.len()];
        self.upload_blob(id.clone() + ".json", upload_val).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let cmd = &args[1];

    let node_addrs = ["http://localhost:50050", "http://localhost:50051", "http://localhost:50052"];

    let cli_id = "user1";
    let app_name = "signing";
    let mut client = Client::new(cli_id);
    client.setup(node_addrs.to_vec(), None);

    let num_parties: u16 = match args[2].parse() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("error: num_parties not a string");
            panic!("");
        }
    };

    let num_threshold: u16 = match args[3].parse() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("error: num_threshold not a string");
            panic!("");
        }
    };

    let key_file: String = match args[4].parse() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("error: key_file not a string");
            panic!("");
        }
    };

    match &cmd[..] {
        "keygen" => {
            client
                .upload_keygen_params(String::from(cli_id), num_threshold, num_parties)
                .await;

            let in_files = [String::from("user1.json")];
            let out_files = [key_file];

            client
                .exec(app_name, "keygen", in_files.to_vec(), out_files.to_vec(), vec![vec![]; num_parties as usize])
                .await?;
        }
        "sign" => {
            let active_parties: String = match args[5].parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("error: active_parties not a string");
                    panic!("");
                }
            };

            let message: String = match args[6].parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("error: message not a string");
                    panic!("");
                }
            };

            let active_parties_str: Vec<&str> = active_parties.split(",").collect();
            let mut active_parties: Vec<u16> = vec![];
            for party in active_parties_str {
                active_parties.push(party.trim_matches(char::from(0)).parse::<u16>().unwrap());
            }

            client
                .upload_sign_params(String::from(cli_id), num_threshold, active_parties, message)
                .await;

            let in_files = [String::from("user1.json"), key_file];
            let out_files = [String::from("signature.json")];

            client
                .exec(app_name, "signing", in_files.to_vec(), out_files.to_vec(), vec![vec![]; num_parties as usize])
                .await?;
        }

        _ => println!("Missing/wrong arguments"),
    };

    Ok(())
}
