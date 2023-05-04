use std::error::Error;
use std::io::prelude::*;

use libdots;

fn main() -> Result<(), Box<dyn Error>> {
    libdots::env::init()?;

    let rank = libdots::env::get_world_rank();
    let func_name = libdots::env::get_func_name();
    let in_files = libdots::env::get_in_files();

    println!("rank {:?}", rank);
    println!("func name {:?}", func_name);

    // testing network connections
    if rank == 0 {
        libdots::msg::send("Hello world".as_bytes(), 1, 0)?;
        let mut buffer = [0; 30];
        libdots::msg::recv(&mut buffer, 1, 0)?;
        println!("{}", String::from_utf8_lossy(&buffer));
        libdots::msg::recv(&mut buffer, 2, 0)?;
        println!("{}", String::from_utf8_lossy(&buffer));
    } else if rank == 1 {
        let mut buffer = [0; 11];
        libdots::msg::recv(&mut buffer, 0, 0)?;
        println!("{}", String::from_utf8_lossy(&buffer));
        libdots::msg::send("Hello from party 1".as_bytes(), 0, 0)?;
    } else {
        libdots::msg::send("Hello from party 2".as_bytes(), 0, 0)?;
    }

    // printing input files
    for mut f in in_files {
        let mut buf = [0; 1024];
        f.read(&mut buf)?;
        println!("file content: {}", String::from_utf8_lossy(&buf));
    }
    Ok(())
    // develop server side application here ...
}
