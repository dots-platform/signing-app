use dtrust::client::Client;

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use async_trait::async_trait;

#[async_trait]
pub trait SecretKeyStorage {
    async fn distribute_sk(&self, key: String, val: i64);
    async fn recover_sk(&self, key: String) -> i64;
}

#[async_trait]
impl SecretKeyStorage for Client {
    async fn distribute_sk(&self, key: String, val: i64) {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut shares = vec![];
        let mut cum_r = 0;
        for _ in 0..self.node_addrs.len()-1 {
            let share: i64 = rng.gen();
            cum_r += share;
            shares.push(share.to_ne_bytes().to_vec());
        }
        shares.push((val - cum_r).to_ne_bytes().to_vec());
        self.upload_blob(key, shares).await;
    }

    async fn recover_sk(&self, key: String) -> i64 {
        let blobs: Vec<Vec<u8>> = self.retrieve_blob(key).await;
        let mut val: i64 = 0;
        for blob in blobs {
            let v: i64 = i64::from_ne_bytes(blob[0..8].try_into().unwrap());
            println!("shares retrieved {:?}", v);
            val += v;
        }
        println!("reconstructed val {:?}", val);
        val
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let use_tls: bool = false;
    let num_parties = 3;
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
    let in_files = [String::from("sk")];

    let cli_id = "user1";
    let app_name = "cpp_app";
    let func_name = "";
    let mut client = Client::new(cli_id);
    
    client.setup(node_addrs.to_vec(), rootca_certpath);
    client.distribute_sk(String::from("sk"), 666).await;
    client.exec(app_name, func_name, in_files.to_vec(), [String::from("out")].to_vec(), vec![vec![]; num_parties]).await?;
    client.recover_sk(String::from("sk")).await;
    
    Ok(())
}
