# Setup

### Installations

Install Rust and GMP arithmetic library:

```jsx
brew install rust
```

```jsx
brew install gmp
```

# Setup Nodes
First configure the server nodes in `server_conf.yml`. Any number of servers can be added. The default configuration runs with three servers;

Ensure that the application configuration stanza is present in the server config. By default, the client uses the application name `signing`. If this repository is cloned as a sibling of the <https://github.com/dtrust-project/dots-server> repo, the following stanza should work:

```yaml
apps:
  signing:
    path: ../signing-app/target/debug/rust_app
```

# Start Nodes
Run the following command in one terminal in the `dots-server` repo.
```bash
./start-n.sh 0 <N-1>
```

Where `<N-1>` is the number of servers minus one, or the index of the last server node.

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

# Register user
Register a user with the given username and password.
```jsx
cargo run --bin client register username password
```

# KeyGen
We will generate keys for a scheme that has 3 separate parties and a threshold of 1 party. In a new terminal, run:

```jsx
cargo run --bin client username password keygen 3 1 key.json
```
The local key shares will be generated as files:
- In `dtrust/signing/files/node1/key.json`, you will find the key for party 1.
- In `dtrust/signing/files/node2/key.json`, you will find the key for party 2.
- In `dtrust/signing/files/node3/key.json`, you will find the key for party 3.

# Signing

We will sign the message `“hello”` by passing in the indices of the parties who attended the signing (`1,2`). In a new terminal, run:

```jsx
cargo run --bin client username password sign 3 1 key.json 1,2 hello
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
