# Dots Application: Distributed Signature Signing

## Installations

Install Rust and GMP arithmetic library:

```jsx
brew install rust
```

```jsx
brew install gmp
```

## Setup Nodes
Before you begin, make sure you set up the workspace following the instructions in [dots-server](https://github.com/dots-platform/dots-server). We assume you have a workspace folder named `dots` and you are in this workspace. First, install the repo in this workspace:

```
git clone https://github.com/dots-platform/signing-app.git
```

Configure the server nodes in `dots-server/server_conf.yml`. Any number of servers can be added. The default configuration runs with three servers, so you should change the server config to set up three servers.

Next, add the `signing` application to the config. By default, the following stanza should work:
```yaml
apps:
  signing:
    path: ../signing-app/target/debug/rust_app
```

## Start Nodes
Run the following command in one terminal in the `dots-server` repo.
```bash
./start-n.sh 0 2
```

## Register user
Register a user with the given username and password.
```jsx
cargo run --bin client register username password
```

## KeyGen
We will generate keys for a scheme that has 3 separate parties and a threshold of 1 party. In a new terminal, run:

```jsx
cargo run --bin client keygen username password 3 1 key.json
```
The local key shares will be generated as files:
- In `dots-server/files/node{i}/key.json`, you will find the key for party i.
## Signing

We will sign the message `“hello”` by passing in the indices of the parties who attended the signing (`1,2`). In a new terminal, run:

```jsx
cargo run --bin client sign username password 3 1 key.json 1,2 hello
```

The joint signature will look something like this:
```jsx
{
   "r":{
      "curve":"secp256k1",
      "scalar":[
         190,
         83,
         147,
         97,
         147,
         24,
         171,
         144,
         225,
         140,
         23,
         29,
         224,
         199,
         108,
         179,
         0,
         20,
         105,
         197,
         99,
         173,
         52,
         136,
         166,
         196,
         94,
         151,
         149,
         223,
         65,
         156
      ]
   },
   "s":{
      "curve":"secp256k1",
      "scalar":[
         37,
         27,
         175,
         251,
         42,
         109,
         130,
         42,
         185,
         37,
         121,
         21,
         159,
         214,
         217,
         8,
         203,
         171,
         149,
         109,
         225,
         71,
         100,
         192,
         182,
         251,
         82,
         12,
         103,
         249,
         111,
         4
      ]
   },
   "recid":0
}
```

## Troubleshooting
MacOS has a [known issue](https://github.com/ZenGo-X/multi-party-ecdsa/issues/66) where `rustc` has trouble locating the `gmp` library. You may see something similar to the following error:

```jsx
ld: library not found for -lgmp
clang: error: linker command failed with exit code 1
```

If this happens, link the library manually by running:

```jsx
export LIBRARY_PATH=$LIBRARY_PATH:/opt/homebrew/lib
export INCLUDE_PATH=$INCLUDE_PATH:/opt/homebrew/include
```
Now, restart the server.
