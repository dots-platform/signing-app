use curv::{arithmetic::Converter, elliptic::curves::Secp256k1, BigInt};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::{
    keygen::{Keygen, LocalKey, ProtocolMessage},
    sign::{
        CompletedOfflineStage, OfflineProtocolMessage, OfflineStage, PartialSignature, SignManual,
    },
};

use libdots::env::Env;
use libdots::request::Request;
use round_based::{Msg, StateMachine};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io::{self, ErrorKind};

const PROTOCOL_MSG_SIZE: usize = 18000;

/// This party receives incoming messages in present round of the keygen protocol
///
/// # Arguments
///
/// * `req` - The current DoTS request
/// * `num_parties` - The number of parties
/// * `party` - KeyGen protocol state machine of current party
/// * `party_index` - Index of current party
fn receive_keygen(
    req: &Request,
    num_parties: u16,
    party: &mut Keygen,
    party_index: u16,
) -> Result<(), Box<dyn Error>> {
    // Receive from to all other recipients
    for sender in 1..(num_parties + 1) {
        let recipient = party_index;
        if recipient != sender {
            let mut result_buf = [0; PROTOCOL_MSG_SIZE];
            req.msg_recv(&mut result_buf, sender as usize - 1, 0)?;

            // Deserialize message
            let received_msg = serde_json::from_str::<Msg<ProtocolMessage>>(
                &String::from_utf8_lossy(&result_buf).trim_matches(char::from(0)),
            )
            .unwrap();

            // Process received broadcast message
            party
                .handle_incoming(received_msg)
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        }
    }
    Ok(())
}

/// Current party receives incoming messages in present round of the signing protocol
///
/// # Arguments
///
/// * `req` - The current DoTS request
/// * `party` - OfflineStage protocol state machine of current party
/// * `party_index` - Index of current party
/// * `active_parties` - Parties participating in producing the signature
fn receive_sign(
    req: &Request,
    party: &mut OfflineStage,
    party_index: u16,
    active_parties: &Vec<u16>,
) -> Result<(), Box<dyn Error>> {
    // Receive from to all other recipients
    for sender in active_parties {
        let recipient = party_index as usize;
        if recipient != *sender as usize {
            let mut result_buf = [0; PROTOCOL_MSG_SIZE];
            req.msg_recv(&mut result_buf, *sender as usize - 1, 0)?;

            // Deserialize message
            let received_msg = serde_json::from_str::<Msg<OfflineProtocolMessage>>(
                &String::from_utf8_lossy(&result_buf).trim_matches(char::from(0)),
            )
            .unwrap();
            // Process received broadcast message
            party
                .handle_incoming(received_msg)
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        }
    }
    Ok(())
}

/// Current party broadcasts a message to all other parties in present round of the keygen protocol
///
/// # Arguments
///
/// * `req` - The current DoTS request
/// * `msg_index` - Index of message which this party is broadcasting to all other parties
/// * `num_parties` - The number of parties
/// * `party` - KeyGen protocol state machine of current party
/// * `party_index` - Index of current party
fn broadcast_keygen(
    req: &Request,
    msg_index: usize,
    num_parties: u16,
    party: &mut Keygen,
    party_index: u16,
) -> Result<(), Box<dyn Error>> {
    let msg = &party.message_queue()[msg_index];

    // Serialize message
    let serialized = serde_json::to_string(&msg).unwrap();

    // Send to all other recipients
    for recipient in 1..(num_parties + 1) {
        let sender = party_index;
        if recipient != sender {
            // Send message to recipient
            req.msg_send(serialized.as_bytes(), recipient as usize - 1, 0)?;
        }
    }
    receive_keygen(req, num_parties, party, party_index)?;
    Ok(())
}

/// Current party broadcasts a message to all other parties in present round of the signing protocol
///
/// # Arguments
///
/// * `req` - The current DoTS request
/// * `msg` - Index of message which this party is broadcasting to all other parties
/// * `num_parties` - The number of parties
/// * `party` - OfflineStage protocol state machine of current party
/// * `party_index` - Index of current party
/// * `active_parties` - Parties participating in producing the signature
fn broadcast_sign(
    req: &Request,
    msg_index: usize,
    party: &mut OfflineStage,
    party_index: u16,
    active_parties: &Vec<u16>,
) -> Result<(), Box<dyn Error>> {
    let msg = &party.message_queue()[msg_index];

    // Serialize message
    let serialized = serde_json::to_string(&msg).unwrap();

    // Send to all other recipients
    for recipient in active_parties {
        let sender = party_index as usize;
        if *recipient != sender as u16 {
            // Send message to recipient
            req.msg_send(serialized.as_bytes(), *recipient as usize - 1, 0)?;
        }
    }
    receive_sign(req, party, party_index, &active_parties)?;
    Ok(())
}

/// Current party sends p2p messages to specific recipients in present round of the keygen protocol
///
/// # Arguments
///
/// * `req` - The current DoTS request
/// * `msg_queue` - Messages this party is sending p2p to specific recipients
/// * `num_parties` - The number of parties
/// * `party` - KeyGen protocol state machine of current party
/// * `party_index` - Index of current party
fn p2p_keygen(
    req: &Request,
    msg_queue: &mut Vec<Msg<ProtocolMessage>>,
    num_parties: u16,
    party: &mut Keygen,
    party_index: u16,
) -> Result<(), Box<dyn Error>> {
    for msg in msg_queue.iter() {
        // Serialize message
        let serialized = serde_json::to_string(&msg).unwrap();

        // Send to intended recipient
        let recipient = msg.receiver.unwrap();
        req.msg_send(serialized.as_bytes(), recipient as usize - 1, 0)?;
    }

    receive_keygen(req, num_parties, party, party_index)?;
    Ok(())
}

/// Current party sends p2p messages to specific recipients in present round of the signing protocol
///
/// # Arguments
///
/// * `req` - The current DoTS request
/// * `msg_queue` - Messages this party is sending p2p to specific recipients
/// * `party` - OfflineStage protocol state machine of current party
/// * `party_index` - Index of current party
/// * `active_parties` - Parties participating in producing the signature
fn p2p_sign(
    req: &Request,
    msg_queue: &mut Vec<Msg<OfflineProtocolMessage>>,
    party: &mut OfflineStage,
    party_index: u16,
    active_parties: &Vec<u16>,
) -> Result<(), Box<dyn Error>> {
    for msg in msg_queue.iter() {
        // Serialize message
        let serialized = serde_json::to_string(&msg).unwrap();

        // Send to intended recipient
        let recipient = msg.receiver.unwrap();
        req.msg_send(serialized.as_bytes(), recipient as usize - 1, 0)?;
    }

    receive_sign(req, party, party_index, active_parties)?;
    Ok(())
}

/// Generates a signature on the message after offline stage is complete
///
/// # Arguments
///
/// * `req` - The current DoTS request
/// * `msg_to_sign` - Message that parties must sign
/// * `party_index` - Index of current party
/// * `offline_output` - CompletedOfflineStage protocol state machine of current party
/// * `active_parties` - Parties participating in producing the signature
fn sign_message(
    req: &Request,
    msg_to_sign: BigInt,
    party_index: u16,
    offline_output: CompletedOfflineStage,
    active_parties: &Vec<u16>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Obtain party's partial share
    let (manual_sign, partial_share) = SignManual::new(msg_to_sign, offline_output).unwrap();

    // Send to all other parties
    // Serialize message
    let serialized = serde_json::to_string(&partial_share).unwrap();

    // Send to all other recipients
    for recipient in active_parties {
        let sender = party_index;
        if *recipient != sender {
            // Send message to recipient
            req.msg_send(serialized.as_bytes(), *recipient as usize - 1, 0)?;
        }
    }

    // Receive everyone else's partial signature shares
    let mut other_partial_shares = vec![];
    for sender in active_parties {
        let recipient = party_index;
        if recipient != *sender {
            let mut result_buf = [0u8; PROTOCOL_MSG_SIZE];
            req.msg_recv(&mut result_buf, *sender as usize - 1, 0)?;

            // Deserialize message
            let received_share = serde_json::from_str::<PartialSignature>(
                &String::from_utf8_lossy(&result_buf).trim_matches(char::from(0)),
            )
            .unwrap();

            // Process received broadcast message
            other_partial_shares.push(received_share);
        }
    }

    let signature = manual_sign.complete(&other_partial_shares).unwrap();
    println!("Signature: {:?}", serde_json::to_string(&signature).unwrap());
    Ok(serde_json::to_vec_pretty(&signature).map_err(|e| io::Error::new(ErrorKind::Other, e))?)
}

/// Generates local key share of the multi-party ECDSA threshold signing scheme for this party
///
/// # Arguments
///
/// * `req` - The current DoTS request
/// * `num_parties` - Total number of parties
/// * `num_threshold` - The threshold t such that the number of honest and online parties must be at least t + 1 to produce a valid signature
/// * `party_index` - Index of current party
fn keygen(
    req: &Request,
    num_parties: u16,
    num_threshold: u16,
    party_index: u16,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Set up current rank's party KeyGen state machine
    let mut party = Keygen::new(party_index, num_threshold, num_parties).unwrap();

    // Round 1
    party
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    broadcast_keygen(req, 0, num_parties, &mut party, party_index)?;

    // Round 2
    broadcast_keygen(req, 1, num_parties, &mut party, party_index)?;
    party
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Round 3
    let mut msg_queue = vec![];
    for i in 0..num_parties - 1 {
        let msg_index = (i + 2) as usize;
        msg_queue.push(party.message_queue()[msg_index].clone());
    }

    p2p_keygen(req, &mut msg_queue, num_parties, &mut party, party_index)?;
    party
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    broadcast_keygen(req, (num_parties + 1) as usize, num_parties, &mut party, party_index)?;
    party
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    let local_key = party.pick_output().unwrap().unwrap();

    Ok(serde_json::to_vec_pretty(&local_key).map_err(|e| io::Error::new(ErrorKind::Other, e))?)
}

/// Generates signature of the multi-party ECDSA threshold signing scheme for this party
///
/// # Arguments
///
/// * `req` - The current DoTS request
/// * `num_threshold` - The threshold t such that the number of honest and online parties must be at least t + 1 to produce a valid signature
/// * `active_parties` - Parties participating in producing the signature
/// * `key` - Local key share of current party generated in the keygen phase of the protocol
/// * `party_index` - Index of current party
/// * `message` - Message that must be signed
fn sign(
    req: &Request,
    num_threshold: u16,
    active_parties: &Vec<u16>,
    key: LocalKey<Secp256k1>,
    party_index: u16,
    message: String,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if !active_parties.contains(&party_index) {
        println!("Party {:?} is not needed in this signature generation.", party_index);
        return Ok(Vec::new());
    }
    // Initiate offline phase
    let mut offline_stage = OfflineStage::new(party_index, active_parties.clone(), key).unwrap();
    offline_stage
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Round 1
    broadcast_sign(req, 0, &mut offline_stage, party_index, &active_parties)?;
    offline_stage
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Round 2
    let mut msg_queue = vec![];
    for i in 0..num_threshold {
        let msg_index = (i + 1) as usize;
        msg_queue.push(offline_stage.message_queue()[msg_index].clone());
    }
    p2p_sign(
        req,
        &mut msg_queue,
        &mut offline_stage,
        party_index,
        &active_parties,
    )?;
    offline_stage
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Round 3
    broadcast_sign(
        req,
        (num_threshold + 1) as usize,
        &mut offline_stage,
        party_index,
        &active_parties,
    )?;
    offline_stage
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Round 4
    broadcast_sign(
        req,
        (num_threshold + 2) as usize,
        &mut offline_stage,
        party_index,
        &active_parties,
    )?;
    offline_stage
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Round 5
    broadcast_sign(
        req,
        (num_threshold + 3) as usize,
        &mut offline_stage,
        party_index,
        &active_parties,
    )?;
    offline_stage
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Round 6
    broadcast_sign(
        req,
        (num_threshold + 4) as usize,
        &mut offline_stage,
        party_index,
        &active_parties,
    )?;
    offline_stage
        .proceed()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Sign message
    let message_int = BigInt::from_bytes(&message.as_bytes());
    let offline_output = offline_stage.pick_output().unwrap().unwrap();
    sign_message(
        req,
        message_int,
        party_index,
        offline_output,
        &active_parties,
    )
}

fn handle_request(env: &Env, req: &Request) -> Result<(), Box<dyn Error>> {
    let rank = env.get_world_rank();
    let func_name = &req.func_name;
    let args = &req.args;

    let party_index = (rank + 1) as u16;
    let params: Value = serde_json::from_slice(&args[0])?;

    // Keygen
    if func_name == "keygen" {
        println!("Generating local key share for party {:?}...", party_index);
        let key = keygen(
            req,
            params["num_parties"].as_u64().unwrap() as u16,
            params["num_threshold"].as_u64().unwrap() as u16,
            party_index,
        )?;
        fs::write(params["key_file"].as_str().unwrap(), &key)?;
        println!("Key generation complete!");

    // Signing
    } else if func_name == "signing" {
        println!("Initiating signature generation for party {:?}...", party_index);
        let key_data = fs::read(params["key_file"].as_str().unwrap())?;
        let key = serde_json::from_slice::<LocalKey<Secp256k1>>(&key_data).unwrap();

        let active_party_iter = params["active_parties"].as_array().unwrap().iter();
        let active_parties : Vec<u16> = active_party_iter.map( |x| x.as_u64().unwrap() as u16).collect();

        let signature = sign(
            req,
            params["num_threshold"].as_u64().unwrap() as u16,
            &active_parties,
            key,
            party_index,
            params["message"].to_string(),
        )?;

        req.output(&signature)?;

        println!("Signature generation complete.");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let env = libdots::env::init()?;

    loop {
        let req = libdots::request::accept()?;
        handle_request(&env, &req)?;
    }
}
