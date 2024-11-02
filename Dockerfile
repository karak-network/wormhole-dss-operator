FROM rust:1.81

WORKDIR /usr/src/app

COPY . .

RUN cargo build wormhole-opertor --release

CMD ["./target/release/wormhole-operator"]