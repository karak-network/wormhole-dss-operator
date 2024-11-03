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

#### Outbound
- Aggregator server URL
- RPC server URLs (Celestia, Network URLs)

### Prerequisites
- Docker
- Geth (to create keystore wallet)

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

### Registering the Operator with Wormhole

Run the following command to register the operator:

```bash
wormhole-operator register \
    --bn254_kms local/aws \
    --bn254_key_path <BN254_KEY_PATH(if local)> \
    --bn254_aws_access_key_id <BN254_AWS_ACCESS_KEY_ID(if aws)> \
    --bn254_aws_secret_access_key <BN254_AWS_SECRET_ACCESS_KEY(if aws)> \
    --bn254_aws_default_region <BN254_AWS_DEFAULT_REGION(if aws)> \
    --bn254_aws_password <BN254_AWS_PASSWORD(if aws)> \
    --bn254_aws_key_name <BN254_AWS_KEY_NAME(if aws)> \
    --eth_kms env/local/aws \
    --eth_private_key <ETH_PRIVATE_KEY(if env)> \
    --eth_keystore_path <ETH_KEYSTORE_PATH(if local)> \
    --eth_aws_key_id <ETH_AWS_KEY_ID(if aws)> \
    --eth_aws_access_key_id <ETH_AWS_ACCESS_KEY_ID(if aws)> \
    --eth_aws_secret_access_key <ETH_AWS_SECRET_ACCESS_KEY(if aws)> \
    --eth_aws_region <ETH_AWS_REGION(if aws)> \
    --eth_aws_key_name <ETH_AWS_KEY_NAME(if aws)> \
```

Alternatively, you can put those arguments in an `.env` file or directly export to your environment and run:

```bash
wormhole-operator register
```

### Registering the Operator with Core

Follow the steps [here](https://docs.karak.network/operators/registration) for Karak Operator registration.

### Deployment

Fill out the `.env` with the following environment variables:

```
LISTEN_ADDR=/ip4/0.0.0.0/tcp/8085
# Pre filled address of bootnode
BOOTSTRAP_NODES='[{peer_id: "12D3KooWNsY2874ai6jVdYAWy3yPCx1MhnRddNwNMn54UEVoA9ik", address: "/ip4/65.1.181.93/tcp/8085"}]'
IDLE_TIMEOUT_DURATION=60
# MODES = LATEST, SAFE
EVENT_SUBSCRIPTION_MODE=SAFE

# METHODS: LOCAL, AWS
BN254_KEYSTORE_METHOD=LOCAL

# FOR LOCAL
BN254_KEY_PATH=

# FOR AWS
BN254_AWS_ACCESS_KEY_ID=
BN254_AWS_SECRET_ACCESS_KEY=
BN254_AWS_DEFAULT_REGION=
BN254_AWS_KEY_NAME=

# METHODS: ENV, LOCAL, AWS
ETH_KEYSTORE_METHOD=ENV

# FOR ENV
ETH_PRIVATE_KEY=

# FOR AWS
ETH_AWS_ACCESS_KEY_ID=
ETH_AWS_SECRET_ACCESS_KEY=
ETH_AWS_DEFAULT_REGION=
ETH_AWS_KEY_NAME=

# FOR LOCAL
ETH_KEYPAIR_PATH=

DB_PATH=
SERVER_PORT=
```

### Running the Binary

1. run 
```bash 
source .env
 ```
2. Run the binary:

```bash 
wormhole-operator run
```

---

That's it! You're all set to run the Wormhole DSS operator. If you encounter any issues, please refer to the documentation or raise an issue on our GitHub repository.
