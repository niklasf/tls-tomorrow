#!/bin/sh -e
cargo +stable build --release --target x86_64-unknown-linux-musl
scp ./target/x86_64-unknown-linux-musl/release/tls-tomorrow "root@$1.lichess.ovh":/usr/local/bin/tls-tomorrow
