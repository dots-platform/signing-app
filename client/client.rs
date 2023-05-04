use dotspb::dec_exec::dec_exec_client::DecExecClient;
use dotspb::dec_exec;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

use tokio::task;
use uuid::Uuid;
use futures::future::join_all;

pub struct Client {
    pub client_id: &'static str,
    pub node_addrs: Vec<&'static str>,
    pub ca_cert_filepath: Option<&'static str>
}

impl Client {
    pub fn new(cli_id: &'static str) -> Self {
        Client { client_id: cli_id, node_addrs : Vec::new(), ca_cert_filepath : None }
    }

    pub fn setup(&mut self, node_addrs: Vec<&'static str>, tls_ca: Option<&'static str>) {
        self.node_addrs = node_addrs;
        self.ca_cert_filepath = tls_ca;
    }

    pub async fn upload_blob(&self, key: String, vals: Vec<Vec<u8>>) {
        let mut futures = vec![];

        for (i, node_addr) in self.node_addrs.iter().enumerate() {
            let fut = task::spawn(Client::upload_blob_single(self.client_id.clone(), node_addr.clone(), self.ca_cert_filepath.clone(), key.clone(), vals[i].clone()));
            futures.push(fut);
        }

        let results = join_all(futures).await;
        println!("Results: {:?}", results);
    }

    pub async fn retrieve_blob(&self, key: String) -> Vec<Vec<u8>> {
        let mut futures = vec![];

        for (_, node_addr) in self.node_addrs.iter().enumerate() {
            let fut = task::spawn(Client::retrieve_blob_single(self.client_id.clone(), node_addr.clone(), self.ca_cert_filepath.clone(), key.clone()));
            futures.push(fut);
        }

        let responses = join_all(futures).await;

        let mut blobs = vec![];
        for res in responses {
            blobs.push(res.unwrap().unwrap());
        }

        println!("Blobs: {:?}", blobs);
        blobs
    }

    pub async fn exec(&self, app_name: &'static str, func_name: &'static str, in_files: Vec<String>, out_files: Vec<String>, args: Vec<Vec<Vec<u8>>>) -> Result<Vec<dec_exec::Result>, Box<dyn std::error::Error>> {

        let mut futures = vec![];

        let request_id = uuid::Uuid::new_v4();

        for i in 0..self.node_addrs.len() {
            let fut = task::spawn(Client::exec_single(request_id, self.client_id.clone(), self.node_addrs[i].clone(), self.ca_cert_filepath.clone(), app_name, func_name, in_files.clone(), out_files.clone(), args[i].clone()));
            futures.push(fut);
        }

        // self.node_ids.iter().map(|s| s.to_string()).collect())

        let results: Vec<Result<dec_exec::Result, Box<dyn std::error::Error>>> = join_all(futures).await
            .into_iter()
            .map(|result| result.expect("Join error").map_err(|e| e as Box<dyn std::error::Error>))
            .collect();
        println!("Results: {:?}", results);

        Result::from_iter(results)
    }

    async fn connect_to_server(node_addr: &'static str, ca_cert_filepath: Option<&'static str>) -> Result<DecExecClient<Channel>, Box<dyn std::error::Error + Send + Sync>> {
        let client =
            match ca_cert_filepath {
                Some(rootca_certpath) => {
                    let pem = tokio::fs::read(rootca_certpath).await?;
                    let ca = Certificate::from_pem(pem);
                    let tls = ClientTlsConfig::new()
                        .ca_certificate(ca);
                    let channel = Channel::from_static(node_addr)
                        .tls_config(tls)?
                        .connect()
                        .await?;
                    DecExecClient::new(channel)
                },
                None => DecExecClient::connect(node_addr).await?
            };
        return Ok(client);
    }

    async fn upload_blob_single(cli_id: &'static str, node_addr: &'static str, ca_cert_filepath: Option<&'static str>, key: String, val: Vec<u8>) -> Result<(), Box<dyn std::error::Error + Send + Sync>>{
        let mut client = Self::connect_to_server(node_addr, ca_cert_filepath).await?;

        let request = tonic::Request::new(dec_exec::Blob {
            key: key,
            val: val,
            client_id: cli_id.to_string(),
        });

        let response = client.upload_blob(request).await?;
        println!("RESPONSE={:?}", response);
        Ok(())
    }

    async fn retrieve_blob_single(cli_id: &'static str, node_addr: &'static str, ca_cert_filepath: Option<&'static str>, key: String) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>{
        let mut client = Self::connect_to_server(node_addr, ca_cert_filepath).await?;

        let request = tonic::Request::new(dec_exec::Blob {
            key: key,
            val: vec![],
            client_id: cli_id.to_string()
        });

        let response = client.retrieve_blob(request).await?;
        println!("Blob={:?}", response);
        Ok(response.into_inner().val)
    }

    async fn exec_single(request_id: Uuid, cli_id: &'static str, node_addr: &'static str, ca_cert_filepath: Option<&'static str>, app_name: &'static str, func_name: &'static str, in_files: Vec<String>, out_files: Vec<String>, args: Vec<Vec<u8>>) -> Result<dec_exec::Result, Box<dyn std::error::Error + Send + Sync>> {
        let mut client = Self::connect_to_server(node_addr, ca_cert_filepath).await?;

        let request_id_hi = u64::from_be_bytes(request_id.as_bytes()[..8].try_into().unwrap());
        let request_id_lo = u64::from_be_bytes(request_id.as_bytes()[8..].try_into().unwrap());

        let request = tonic::Request::new(dec_exec::App {
            app_name: app_name.into(),
            app_uid: 0,
            func_name: func_name.into(),
            in_files: in_files,
            out_files: out_files,
            client_id: cli_id.to_string(),
            request_id: Some(dec_exec::Uuid {
                hi: request_id_hi,
                lo: request_id_lo,
            }),
            args: args,
        });

        let response = client.exec(request).await?;
        println!("RESPONSE={:?}", response);

        Ok(response.into_inner())
    }
}
