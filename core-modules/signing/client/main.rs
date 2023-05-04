use std::env;

use dtrust::client::Client;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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

    let use_tls: bool = true;

    let node_addrs =
        if use_tls == true {
            ["https://node1.test:50051", "https://node2.test:50052", "https://node3.test:50053"]
        } else {
            ["http://127.0.0.1:50051", "http://127.0.0.1:50052", "http://127.0.0.1:50053"]
        };
    let rootca_certpath =
        if use_tls == true {
            Some("tls_certs/myCA.pem")
        } else {
            None
        };

    let cli_id = "user1";
    let app_name = "rust_app";
    let mut client = Client::new(cli_id);
    client.setup(node_addrs.to_vec(), rootca_certpath);

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
