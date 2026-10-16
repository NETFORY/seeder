rm nohup.out
pkill smartnet-seeder
RUST_LOG=smartnet_seeder=info,iroh=info nohup ./target/release/smartnet-seeder &
