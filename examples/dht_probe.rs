// Reproduction of the client DHT monitor logic: extra_bootstrap (preserves default
// public routers) + build on blocking pool + bootstrapped + routing_table_size.
// Expected: DHT_NODES > 0 (entry into Mainline via default routers even if
// SmartNet node is unavailable). This proves the fix for the "0 nodes" regression.
use n0_mainline::Dht;

#[tokio::main]
async fn main() {
    // Exactly as in the client: SmartNet IP is added ON TOP of default routers.
    let extra: Vec<String> = vec!["116.202.32.250:6881".to_string()];
    let built = tokio::task::spawn_blocking(move || {
        let mut mdb = Dht::builder();
        mdb.extra_bootstrap(&extra);
        mdb.build()
    })
    .await;
    let dht = match built {
        Ok(Ok(d)) => d,
        other => {
            println!("BUILD_FAILED: {:?}", other.map(|r| r.map(|_| ())));
            std::process::exit(1);
        }
    };
    let _ = dht.bootstrapped().await;
    let mut last = 0u64;
    for _ in 0..4 {
        if let Ok(info) = dht.info().await {
            last = info.routing_table_size() as u64;
            println!("DHT_NODES={}", last);
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    if last > 0 {
        println!("RESULT=PASS nodes={}", last);
    } else {
        println!("RESULT=FAIL nodes=0");
        std::process::exit(2);
    }
}
