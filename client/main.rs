use std::env;
use std::error::Error;

use dotspb::dec_exec::dec_exec_client::DecExecClient;
use dotspb::dec_exec::App;
use futures::future;
use serde::{Deserialize, Serialize};
use tonic::transport::Channel;
use tonic::Request;
use uuid::Uuid;

const APP_NAME: &str = "signing";

fn uuid_to_uuidpb(id: Uuid) -> dotspb::dec_exec::Uuid {
    dotspb::dec_exec::Uuid {
        hi: (id.as_u128() >> 64) as u64,
        lo: id.as_u128() as u64,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Params {
    K {
        key_file: String,
        num_parties: u16,
        num_threshold: u16,
    },
    S {
        key_file: String,
        num_threshold: u16,
        active_parties: Vec<u16>,
        message: String,
    },
}

async fn keygen(
    clients: &mut [DecExecClient<Channel>],
    key_file: &str,
    num_parties: u16,
    num_threshold: u16,
) -> Result<(), Box<dyn Error>> {
    let params = Params::K {
        key_file: key_file.to_owned(),
        num_parties,
        num_threshold,
    };
    let params_json = serde_json::to_vec(&params)?;

    let request_id = Uuid::new_v4();
    future::join_all(
            clients
                .iter_mut()
                .map(|client|
                    client.exec(Request::new(App {
                        app_name: APP_NAME.to_owned(),
                        app_uid: 0,
                        request_id: Some(uuid_to_uuidpb(request_id)),
                        client_id: "".to_owned(),
                        func_name: "keygen".to_owned(),
                        in_files: vec![],
                        out_files: vec![],
                        args: vec![params_json.clone()],
                    }))
                )
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    Ok(())
}

async fn sign(
    clients: &mut [DecExecClient<Channel>],
    key_file: &str,
    num_threshold: u16, 
    active_parties: &[u16],
    message: &str,
) -> Result<(), Box<dyn Error>> {
    let params = Params::S {
        key_file: key_file.to_owned(),
        num_threshold,
        active_parties: active_parties.to_owned(),
        message: message.to_owned(),
    };
    let params_json = serde_json::to_vec(&params)?;

    let request_id = Uuid::new_v4();
    future::join_all(
            clients
                .iter_mut()
                .map(|client|
                    client.exec(Request::new(App {
                        app_name: APP_NAME.to_owned(),
                        app_uid: 0,
                        request_id: Some(uuid_to_uuidpb(request_id)),
                        client_id: "".to_owned(),
                        func_name: "signing".to_owned(),
                        in_files: vec![],
                        out_files: vec![],
                        args: vec![params_json.clone()],
                    }))
                )
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let cmd = &args[1];

    let node_addrs = ["http://localhost:50050", "http://localhost:50051", "http://localhost:50052"];

    let mut clients = future::join_all(
            node_addrs
                .iter()
                .map(|addr| DecExecClient::connect(addr.clone()))
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

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
            keygen(&mut clients, &key_file, num_parties, num_threshold).await?;
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

            let active_parties: Vec<u16> = active_parties.split(",")
                .map(|s| s.parse::<u16>().unwrap())
                .collect();

            sign(&mut clients, &key_file, num_threshold, &active_parties, &message).await?;
        }

        _ => println!("Missing/wrong arguments"),
    };

    Ok(())
}
