# Setup

### Installations

Install Rust and GMP arithmetic library:

```jsx
brew install rust
```

```jsx
brew install gmp
```

# Initialize Decentralized Nodes
In the `dtrust` folder, start 3 nodes in three separate terminals:
```jsx
./platform/init_server --node_id node1 --config ./core-modules/signing/server_conf.yml
```

```jsx
./platform/init_server --node_id node2 --config ./core-modules/signing/server_conf.yml
```

```jsx
./platform/init_server --node_id node3 --config ./core-modules/signing/server_conf.yml
```


# Start Server
`cd` into `core-modules/signing`. Start the server:
```jsx
cargo build
cargo run --bin rust_app
```

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

# KeyGen
We will generate keys for a scheme that has 3 separate parties and a threshold of 1 party. In a new terminal, run:

```jsx
cargo run --bin client keygen 3 1 key.json
```
The local key shares will be generated as files:
- In `dtrust/signing/files/node1/key.json`, you will find the key for party 1.
- In `dtrust/signing/files/node2/key.json`, you will find the key for party 2.
- In `dtrust/signing/files/node3/key.json`, you will find the key for party 3.

# Signing

We will sign the message `“hello”` by passing in the indices of the parties who attended the signing (`1,2`). In a new terminal, run:

```jsx
cargo run --bin client sign 3 1 key.json 1,2 hello
```
The resulting signature will be generated as a file:
- In `dtrust/signing/files/node1/signature.json`, you will find the joint signature.
- In `dtrust/signing/files/node2/signature.json`, you will find the joint signature.
- In `dtrust/signing/files/node3/signature.json`, you will find nothing (not an active party).

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
