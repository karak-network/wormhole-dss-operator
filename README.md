# Wormhole DSS

## Operator Setup Guide

This guide will help you set up and run the Wormhole DSS Operator.

### System Requirements (Recommended)
- **Memory**: 4 GB
- **Storage**: 30 GB
- **vCPU**: 2
- **OS**: Ubuntu 18.04 and above

### Network Configuration

#### Inbound
- **Public IP/URL**: Used in the `HOST` variable of the environment


### Installation

Run the following command to download the binaries:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/karak-network/wormhole-dss-operator/releases/download/wormhole-operator-v0.0.1/wormhole-operator-installer.sh | sh
````

The script will place these binaries in the `$HOME/.karak/bin` directory and add this directory to your `$PATH` variable.

### Config File setup

For both running and registering an operator you need to have a `config.json` file in the directory you run the binary in following the format:

```bash
{
    "chains": [{
        "name": "Ethereum Sepolia",
        "wormhole_chain_id": 10002,
        "wormhole_dss_address": "0xb725593Cba23f8d5D5EA9122afaD360dE34716c2",
        "core_address": "0xb3E2dA61df98E44457190383e1FF13e1ea13280b",
        "ws_rpc_url": "<WS_RPC_URL>",
        "listen": true
    },
    {
        "name": "Arbitrum Sepolia",
        "wormhole_chain_id": 10003,
        "wormhole_dss_address": "0x22E5941D466B9EAe55744de12A80d1c4F48eb5BD",
        "core_address": "0x792a05d0687195a96FA49446275569b539271340",
        "ws_rpc_url": "<WS_RPC_URL>",
        "listen": true
    }
]
}
```
_Note: The binary will register and listen only to the chains that have listen as true in the config file._

## Setup Operator

### Create keystores (optional)

#### Local Keystores
If you decide to have local keystores for your bn254 keypair and eth keypair, you can create them using the following commands:

```bash
karak keypair generate --keystore local --curve bn254
karak keypair generate --keystore local --curve eth
```

### Create a vault

Run the following command to create a vault:

- Using local keystore:

```bash
karak operator create-vault \
    --assets <ASSETS> \
    --core-address <CORE_ADDRESS> \
    --secp256k1-keystore-path <KEYSTORE_PATH> \
    --rpc-url <RPC_URL>
```

where `<ASSETS>` is a comma-separated list of asset addresses.

For Sepolia, you can use these addresses:

1. Core contract address: `0xb3E2dA61df98E44457190383e1FF13e1ea13280b`

2. Allow listed assets:
    - `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`
    - `0x8c843B3A8e9A99680b7611612998799966141841`
    - `0xac8910BEf6c73d30B79e7045ea4fB43fF94833eE`
    - `0xf0091d2b18BabAE32A1B24944f653e69Ac99b7d2`

### (Optional) Deposit to vault

Run the following command to deposit to a vault:

```bash
karak operator deposit-to-vault \
    --vault-address <VAULT_ADDRESS> \
    --amount <AMOUNT> \
    --secp256k1-keystore-path <KEYSTORE_PATH>
    --rpc-url <RPC_URL>
```

where `<VAULT_ADDRESS>` is one of the vault addresses created in the previous step.

Note that you'll need to own at least `AMOUNT` of the asset to deposit.
You can get some of the USDC asset (`0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`) from [here](https://faucet.circle.com/).
For the other assets, you can mint them yourself.

<!-- TODO: Add mint command -->

### Stake the vault to Wormhole DSS

#### Request update stake

First, we request an update stake by running:

```bash
karak operator request-stake-update \
    --vault-address <VAULT_ADDRESS> \
    --dss-address <WORMHOLE_DSS_ADDRESS> \
    --stake-update-type stake \
    --core-address <CORE_ADDRESS> \
    --secp256k1-keystore-path <KEYSTORE_PATH> \
    --rpc-url <RPC_URL>
```

This command will return a nonce and a start timestamp in the output.

#### Finalize stake update

Then, we finalize the stake update by running:

```bash
karak operator finalize-stake-update \
    --vault-address <VAULT_ADDRESS> \
    --dss-address <WORMHOLE_DSS_ADDRESS> \
    --stake-update-type stake \
    --nonce <NONCE> \
    --start-timestamp <START_TIMESTAMP> \
    --core-address <CORE_ADDRESS> \
    --secp256k1-keystore-path <KEYSTORE_PATH> \
    --rpc-url <RPC_URL>
```

where

- `<VAULT_ADDRESS>` is one of the vault addresses created earlier
- `<NONCE>` is the nonce returned from the previous command.
- `<START_TIMESTAMP>` is the start timestamp returned from the previous command.

For Sepolia, you can use these addresses:

- `WORMHOLE_DSS_ADDRESS`: `0x0e64c3c675dae7537A9fC1E925E2a87e164f7f53`
- `CORE_ADDRESS`: `0xb3E2dA61df98E44457190383e1FF13e1ea13280b`

Note: You can also use AWS KMS instead of a local keystore. Run

```bash
karak operator --help
```

to see all the available options.

### Registering the Operator with Core

Follow the steps [here](https://docs.karak.network/operators/registration) for Karak Operator registration.


### Registering the Operator with Wormhole
Run the following command to register the operator:

__You need to have Eth for gas on all the chains you want to register to__

```bash
wormhole-operator register \
    --bn254-kms local/aws \
    --bn254-keystore-path <BN254_KEY_PATH(if local)> \
    --bn254-aws-access-key_id <BN254_AWS_ACCESS_KEY_ID(if aws)> \
    --bn254-aws-secret-access-key <BN254_AWS_SECRET_ACCESS_KEY(if aws)> \
    --bn254-aws-default-region <BN254_AWS_DEFAULT_REGION(if aws)> \
    --bn254-aws-password <BN254_AWS_PASSWORD(if aws)> \
    --bn254-aws-key-name <BN254_AWS_KEY_NAME(if aws)> \
    --eth-kms env/local/aws \
    --eth-private-key <ETH_PRIVATE_KEY(if env)> \
    --eth-keystore-path <ETH_KEYSTORE_PATH(if local)> \
    --eth-aws-key-id <ETH_AWS_KEY_ID(if aws)> \
    --eth-aws-access-key-id <ETH_AWS_ACCESS_KEY_ID(if aws)> \
    --eth-aws-secret-access-key <ETH_AWS_SECRET_ACCESS_KEY(if aws)> \
    --eth-aws-region <ETH_AWS_REGION(if aws)> \
    --eth-aws-key-name <ETH_AWS_KEY_NAME(if aws)> \
```

Example using bn254 local keystore and eth local keystore:

```bash
wormhole-operator register\
    --bn254-keystore-path bls_keypair.keypair \
    --eth-keystore-path ~/.karak/0xE78a315E5FC205cE64c7a5f8ad88AC5E2Bc2F826.json
```

Alternatively, you can put those arguments in an `.env` file or directly export to your environment and run:

```bash
wormhole-operator register
```

### Deployment

_Boot Node_ :
```
BOOTSTRAP_NODES = "[{peer_id: "12D3KooWEwGHWScxxked9JmLDo1yCvoFvSvRGQ6snvBizSH7ffYj", address: "/ip4/65.1.181.93/tcp/8085"}]"
```

Fill out the `.env` with the following environment variables:

```
LISTEN_ADDR=/ip4/0.0.0.0/tcp/8085
BOOTSTRAP_NODES='[{peer_id: "12D3KooWEwGHWScxxked9JmLDo1yCvoFvSvRGQ6snvBizSH7ffYj", address: "/ip4/65.1.181.93/tcp/65056"}]'
IDLE_TIMEOUT_DURATION=
DB_PATH=
SERVER_PORT=

# MODES = LATEST, SAFE
EVENT_SUBSCRIPTION_MODE=

# METHODS: LOCAL, AWS
BN254_KMS=

# FOR LOCAL
BN254_KEYSTORE_PATH=

# FOR AWS
BN254_AWS_ACCESS_KEY_ID=
BN254_AWS_SECRET_ACCESS_KEY=
BN254_AWS_DEFAULT_REGION=
BN254_AWS_KEY_NAME=

# METHODS: ENV, LOCAL, AWS
ETH_KMS=

# FOR ENV
ETH_PRIVATE_KEY=

# FOR AWS
ETH_AWS_ACCESS_KEY_ID=
ETH_AWS_SECRET_ACCESS_KEY=
ETH_AWS_DEFAULT_REGION=
ETH_AWS_KEY_NAME=

# FOR LOCAL
ETH_KEYSTORE_PATH=

```

### Running the Binary

1. Keep the `.env` file in the directory you run the binary in. Or export the environment variables using:
```bash 
source .env
 ```
2. Run the binary:

```bash 
wormhole-operator run \
    --bn254-kms local/aws \
    --bn254-keystore-path <BN254_KEY_PATH(if local)> \
    --bn254-aws-access-key-id <BN254_AWS_ACCESS_KEY_ID(if aws)> \
    --bn254-aws-secret-access-key <BN254_AWS_SECRET_ACCESS_KEY(if aws)> \
    --bn254-aws-default-region <BN254_AWS_DEFAULT_REGION(if aws)> \
    --bn254-aws-password <BN254_AWS_PASSWORD(if aws)> \
    --bn254-aws-key-name <BN254_AWS_KEY_NAME(if aws)> \
    --eth-kms env/local/aws \
    --eth-private-key <ETH_PRIVATE_KEY(if env)> \
    --eth-keystore-path <ETH_KEYSTORE_PATH(if local)> \
    --eth-aws-key-id <ETH_AWS_KEY_ID(if aws)> \
    --eth-aws-access-key-id <ETH_AWS_ACCESS_KEY_ID(if aws)> \
    --eth-aws-secret-access-key <ETH_AWS_SECRET_ACCESS_KEY(if aws)> \
    --eth-aws-region <ETH_AWS_REGION(if aws)> \
    --eth-aws-key-name <ETH_AWS_KEY_NAME(if aws)> \
    --p2p-listen-address <LISTEN_ADDR> \
    --bootstrap-nodes <BOOTSTRAP_NODES(with quotes around the string)> \
    --idle-timeout-duration <IDLE_TIMEOUT_DURATION> \
    --event-subscription-mode <EVENT_SUBSCRIPTION_MODE> \
    --db-path <DB_PATH> \
    --server-port <SERVER_PORT>
```

Example using bn254 local keystore and eth local keystore:

```bash
wormhole-operator run \
    --bn254-keystore-path bls_keypair.keypair \
    --eth-keystore-path ~/.karak/0xE78a315E5FC205cE64c7a5f8ad88AC5E2Bc2F826.json
    --event-subscription-mode latest \
    --p2p-listen-address /ip4/0.0.0.0/tcp/8085 \
    --bootstrap-nodes "[{peer_id: "12D3KooWEwGHWScxxked9JmLDo1yCvoFvSvRGQ6snvBizSH7ffYj", address: "/ip4/65.1.181.93/tcp/8085"}]" \
    --idle-timeout-duration 60 \
    --server-port 3000 \
    --db-path wormhole.db \
```

---

That's it! You're all set to run the Wormhole DSS operator. If you encounter any issues, please refer to the documentation or raise an issue on our GitHub repository.
