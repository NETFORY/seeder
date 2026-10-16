// Author: TechnoL0g
// Project: SmartNet Core
// Date: 2026-06-19
/*
 * SmartNet // smartnet-seeder
 *
 *   Headless, GUI-less P2P seeder for the SmartNet network. Runs on any
 *   cheap VPS (no X / no webkit): it joins the iroh-blobs swarm, learns the
 *   app directory from the HTTP trackers, pulls each app's content-addressed
 *   tar blob and re-serves the IDENTICAL blob 24/7 — multiplying availability
 *   ("seeding") so dApps stay reachable even when their authors are offline.
 *
 *   It speaks the exact same wire protocol as the desktop client:
 *     - iroh Endpoint (preset N0 + LAN mDNS address lookup), BlobsProtocol
 *       served over `iroh_blobs::ALPN`.
 *     - tracker POST /announce { node, endpointId, apps[...] } heartbeat and
 *       GET /apps directory fetch. The signed {merkle, signature, publicKey}
 *       are read out of each app's content.json (inside the tar) so the
 *       seeder's relay re-announce verifies on the tracker unchanged.
 *
 *   Config (config.yaml, auto-created on first run): storage budget (default
 *   5 GB), tracker list, and a reward address OR passphrase — reserved for the
 *   upcoming seeding-reward / proof-of-storage system.
 *
 *   Author: TechnoL0g
 *   Created: 2026-06-18
 */

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iroh::endpoint::presets;
use iroh::{protocol::Router, Endpoint, EndpointId};
use iroh_blobs::store::fs::options::Options;
use iroh_blobs::store::{GcConfig, ProtectCb, ProtectOutcome};
use iroh_blobs::api::proto::BlobStatus;
use iroh_blobs::{store::fs::FsStore, BlobsProtocol, Hash};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use n0_mainline::Dht;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

mod media;

/// Версия бинарника (из Cargo.toml) — показывается на статус-странице и в /metrics.
const VERSION: &str = env!("CARGO_PKG_VERSION");

const DEFAULT_TRACKERS: &[&str] = &[
    "http://159.69.188.60:7374",
    "http://91.99.119.119:7374",
    "http://212.193.6.217:7374",
    "http://146.103.108.25:7374",
];

// ============================================================
//  Config
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    /// where blobs + state live (created if missing).
    data_dir: String,
    /// max disk to use for seeded blobs, in gigabytes.
    storage_limit_gb: f64,
    /// HTTP trackers to learn the directory from + announce to.
    trackers: Vec<String>,
    /// SmartHoldem `S...` address that should receive future seeding rewards.
    #[serde(default)]
    reward_address: String,
    /// OR a passphrase to derive the reward address from (same scheme as the
    /// SmartNet wallet: address = base58check(0x3F ‖ ripemd160(secp256k1 pub
    /// of sha256(passphrase)))). Ignored if `reward_address` is set.
    #[serde(default)]
    reward_passphrase: String,
    /// seconds between directory refresh + announce heartbeats.
    poll_interval_secs: u64,
    /// hide this node's direct IP (relay-only, no LAN mDNS advertise/resolve).
    #[serde(default)]
    relay_only: bool,
    /// HTTP port for the /metrics + status page (0 disables it).
    #[serde(default = "default_metrics_port")]
    metrics_port: u16,
    /// public URL where this node's /metrics is reachable, used by the
    /// Network Map leaderboard. Leave empty to auto-detect the public IP on
    /// startup (http://<detected_ip>:<metrics_port>/metrics).
    #[serde(default)]
    public_metrics_url: String,
    /// how often to print a one-line seeding summary to the log.
    #[serde(default = "default_metrics_interval")]
    metrics_interval_secs: u64,
    /// how often (secs) to garbage-collect unused blobs from the store.
    #[serde(default = "default_gc_interval")]
    gc_interval_secs: u64,
    /// Run a public SmartNet Mainline DHT bootstrap node (server mode, open UDP).
    /// Lets clients/providers behind NAT or closed UDP egress join the DHT via
    /// this seeder's infrastructure — independent of n0/n1 and public BT routers.
    #[serde(default = "default_dht_enabled")]
    dht_enabled: bool,
    /// UDP port for the DHT bootstrap node (open this in the firewall). Bake the
    /// pair `<public_ip>:<dht_port>` into client .env (SMARTNET_DHT_BOOTSTRAP) and
    /// provider config.yaml (network.dht_bootstrap) so others bootstrap via it.
    #[serde(default = "default_dht_port")]
    dht_port: u16,
    /// Медиа мессенджера Netfory (фото/аудио/файлы/видео чатов): бюджет в ГБ под
    /// ОТДЕЛЬНОЕ хранилище <data_dir>/media-blobs с отдельным iroh-endpoint.
    /// 0 = выключено (по умолчанию). Напр. 5 = 5 ГБ. При заполнении >90% удаляются
    /// 50% самых старых медиа. Клиенты анонсируют медиа через POST /media/announce.
    #[serde(default)]
    media_storage_gb: f64,
}

fn default_dht_enabled() -> bool {
    true
}
fn default_dht_port() -> u16 {
    6881
}

fn default_metrics_port() -> u16 {
    9466
}
fn default_gc_interval() -> u64 {
    600
}

fn default_metrics_interval() -> u64 {
    300
}

impl Default for Config {
    fn default() -> Self {
        Config {
            data_dir: "./smartnet-seed-data".to_string(),
            storage_limit_gb: 5.0,
            trackers: DEFAULT_TRACKERS.iter().map(|s| s.to_string()).collect(),
            reward_address: String::new(),
            reward_passphrase: String::new(),
            poll_interval_secs: 30,
            relay_only: false,
            metrics_port: default_metrics_port(),
            public_metrics_url: String::new(),
            metrics_interval_secs: default_metrics_interval(),
            gc_interval_secs: default_gc_interval(),
            dht_enabled: default_dht_enabled(),
            dht_port: default_dht_port(),
            media_storage_gb: 0.0,
        }
    }
}

impl Config {
    fn storage_limit_bytes(&self) -> u64 {
        (self.storage_limit_gb.max(0.1) * 1_000_000_000.0) as u64
    }
    /// Resolve the reward address (explicit, else derived from passphrase).
    fn resolved_reward_address(&self) -> String {
        if !self.reward_address.trim().is_empty() {
            return self.reward_address.trim().to_string();
        }
        let p = self.reward_passphrase.trim();
        if p.is_empty() {
            String::new()
        } else {
            address_from_secret(p)
        }
    }
}

/// Load config.yaml; if absent, write a documented default and use it.
fn load_or_init_config(path: &Path) -> Config {
    if let Ok(text) = std::fs::read_to_string(path) {
        match serde_yaml::from_str::<Config>(&text) {
            Ok(c) => return c,
            Err(e) => {
                tracing::warn!("invalid {} ({}), using defaults", path.display(), e);
                return Config::default();
            }
        }
    }
    let cfg = Config::default();
    if let Ok(yaml) = serde_yaml::to_string(&cfg) {
        let banner = "# SmartNet seeder configuration.\n# storage_limit_gb: disk budget for seeded dApp blobs.\n# media_storage_gb: budget for Netfory chat media (0 = off; e.g. 5 = 5 GB, separate store).\n# reward_address / reward_passphrase: where future seeding rewards go.\n";
        let _ = std::fs::write(path, format!("{}{}", banner, yaml));
        tracing::info!("wrote default config to {}", path.display());
    }
    cfg
}

// ============================================================
//  SmartHoldem reward-address derivation (wallet-compatible)
// ============================================================

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn address_from_secret(secret: &str) -> String {
    let sk = match SecretKey::from_slice(&sha256(secret.trim().as_bytes())) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let secp = Secp256k1::signing_only();
    let comp = PublicKey::from_secret_key(&secp, &sk).serialize();
    let mut rip = Ripemd160::new();
    rip.update(comp);
    let hash = rip.finalize();
    let mut payload = Vec::with_capacity(21);
    payload.push(0x3f); // SmartHoldem network byte
    payload.extend_from_slice(&hash);
    bs58::encode(payload).with_check().into_string()
}

// ============================================================
//  Wire types
// ============================================================

/// Subset of an app's content.json we need to relay a signed announce.
#[derive(Debug, Clone, Deserialize)]
struct Manifest {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    merkle: String,
    #[serde(default)]
    version: Option<u32>,
    signature: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    /// developer address (manifest owner) — relayed for the Official Repository.
    #[serde(default)]
    owner: String,
    /// приватный (E2EE) dApp — в ре-анонс кладётся reveal-payload из access.json
    #[serde(default)]
    private: Option<bool>,
}

/// Tracker GET /apps response item.
#[derive(Debug, Deserialize)]
struct AppOut {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: u32,
    /// Phase D: seeding priority (100 base for paid + 1 per boosted STH).
    #[serde(rename = "priorityWeight", default)]
    priority_weight: u32,
    /// Phase D: accumulated boost pool (smarthoshi).
    #[serde(rename = "boostPool", default)]
    boost_pool: u64,
    /// Phase G: оплачен ли активный период сидинга.
    #[serde(default)]
    paid: bool,
    /// Phase G: секунд до конца оплаченного 5-дневного окна (0 = период истёк).
    #[serde(rename = "secondsRemaining", default)]
    seconds_remaining: u64,
    #[serde(default)]
    providers: Vec<ProviderOut>,
}

#[derive(Debug, Deserialize)]
struct ProviderOut {
    #[serde(rename = "endpointId")]
    endpoint_id: String,
    #[serde(default)]
    hash: String,
    #[serde(default)]
    version: u32,
}

/// Tracker POST /announce body (mirrors the desktop client).
/// A single download target with its seeding priority (Phase D).
/// Phase G: headless-сидер начинает удалять приложения с истёкшим оплаченным
/// периодом, когда занятость выделенного диска превышает этот порог (90%).
/// Home/client-ноды этот бинарь НЕ запускают — их набор раздачи не трогается.
const SEEDER_EVICT_FILL_RATIO: f64 = 0.90;

#[derive(Debug, Clone)]
struct Target {
    /// candidate provider endpoint ids that serve `hash` (tried in order until
    /// one actually delivers the blob — a provider may announce an app it no
    /// longer has, so we must fall back to the others).
    eids: Vec<String>,
    hash: String,
    ver: u32,
    name: String,
    weight: u32,
    boost: u64,
}

/// Global monetization kill-switch (default ON). ENABLE_INCENTIVIZED_SEEDING=
/// 0/false/off/no disables priority-weighted eviction (standard P2P seeding).
fn incentivized_enabled() -> bool {
    std::env::var("ENABLE_INCENTIVIZED_SEEDING")
        .map(|v| !matches!(v.trim().to_lowercase().as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(true)
}

// ============================================================
//  Official Repository — on-chain registries (trusted developers +
//  approved dApps). Scanned on boot + every 24h; kept in memory for
//  logging/metrics. Filtering is CLIENT-side (seeders mark, not censor).
// ============================================================

const OFFICIAL_ADMIN: &str = "SeZLuyhhYf2qxs4ArPJ71oEu3x8EsVw51C";
const OFFICIAL_DEVS_ADDR: &str = "SdevsH3kMbcCFWnyYVtD2UYnBQQm66MxDn";
const OFFICIAL_DAPPS_ADDR: &str = "SdAppjWaQf4v2JjuubvtwsKe3yuUCuq8i8";

static OFFICIAL: std::sync::OnceLock<std::sync::Mutex<(HashSet<String>, HashSet<String>)>> =
    std::sync::OnceLock::new();

fn official_sets() -> &'static std::sync::Mutex<(HashSet<String>, HashSet<String>)> {
    OFFICIAL.get_or_init(|| std::sync::Mutex::new((HashSet::new(), HashSet::new())))
}

fn official_scan_registry(recipient: &str) -> Result<Vec<String>, String> {
    let nodes: Vec<String> = std::env::var("SMARTHOLDEM_NODES")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| {
            vec![
                "node0.smartholdem.io".into(),
                "node1.smartholdem.io".into(),
                "node2.smartholdem.io".into(),
                "node3.smartholdem.io".into(),
                "node0.sth.cx".into(),
            ]
        });
    let mut last_err = String::from("no nodes");
    for host in nodes {
        let url = format!(
            "https://{}/api/transactions?recipientId={}&senderId={}&page=1&limit=100&orderBy=timestamp:desc",
            host, recipient, OFFICIAL_ADMIN
        );
        match ureq::get(&url).timeout(Duration::from_secs(12)).call() {
            Ok(r) => {
                // без feature "json" у ureq: читаем строку и парсим сами
                let txt = match r.into_string() {
                    Ok(t) => t,
                    Err(e) => {
                        last_err = e.to_string();
                        continue;
                    }
                };
                let v: serde_json::Value = match serde_json::from_str(&txt) {
                    Ok(v) => v,
                    Err(e) => {
                        last_err = e.to_string();
                        continue;
                    }
                };
                let mut out: Vec<String> = Vec::new();
                if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
                    for tx in arr {
                        if tx.get("sender").and_then(|s| s.as_str()) != Some(OFFICIAL_ADMIN) {
                            continue;
                        }
                        let vf = tx
                            .get("vendorField")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        let ok = vf.len() >= 26
                            && vf.len() <= 40
                            && vf.starts_with('S')
                            && vf.chars().all(|c| c.is_ascii_alphanumeric());
                        if ok && !out.contains(&vf) {
                            out.push(vf);
                        }
                    }
                }
                return Ok(out);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

fn official_refresh() -> Result<(usize, usize), String> {
    let devs_addr =
        std::env::var("OFFICIAL_DEVELOPERS").unwrap_or_else(|_| OFFICIAL_DEVS_ADDR.to_string());
    let dapps_addr =
        std::env::var("OFFICIAL_DAPPS").unwrap_or_else(|_| OFFICIAL_DAPPS_ADDR.to_string());
    let devs = official_scan_registry(&devs_addr)?;
    let dapps = official_scan_registry(&dapps_addr)?;
    let mut dev_set: HashSet<String> = std::env::var("DEVELOPERS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    dev_set.insert(OFFICIAL_ADMIN.to_string());
    dev_set.extend(devs);
    let dapp_set: HashSet<String> = dapps.into_iter().collect();
    let n = (dev_set.len(), dapp_set.len());
    *official_sets().lock().unwrap() = (dev_set, dapp_set);
    Ok(n)
}

/// Boot + 24h scanner (10-min retry while the blockchain is unreachable).
fn spawn_official_scanner() {
    tokio::spawn(async {
        loop {
            let res = tokio::task::spawn_blocking(official_refresh).await;
            let sleep = match res {
                Ok(Ok((d, a))) => {
                    tracing::info!("official registry: {} developers, {} approved dapps", d, a);
                    Duration::from_secs(86_400)
                }
                Ok(Err(e)) => {
                    tracing::warn!("official registry scan failed: {} — retry in 10 min", e);
                    Duration::from_secs(600)
                }
                Err(_) => Duration::from_secs(600),
            };
            tokio::time::sleep(sleep).await;
        }
    });
}


#[derive(Debug, Serialize)]
struct AnnounceApp {
    id: String,
    name: String,
    description: String,
    tags: Vec<String>,
    merkle: String,
    version: u32,
    hash: String,
    signature: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    /// developer address (manifest owner) — Official Repository passthrough.
    #[serde(default)]
    owner: String,
}

#[derive(Debug, Serialize)]
struct AnnounceReq {
    node: String,
    #[serde(rename = "endpointId")]
    endpoint_id: String,
    /// public /metrics URL so the tracker's Network Map can rank this seeder.
    #[serde(rename = "metricsUrl")]
    metrics_url: String,
    apps: Vec<AnnounceApp>,
    /// Our public DHT bootstrap addr (ip:port) so the tracker can auto-distribute
    /// us as a working seeder via GET /seeders-dht. Empty when DHT is off.
    #[serde(rename = "seederDht", skip_serializing_if = "String::is_empty")]
    seeder_dht: String,
}

/// What we currently seed for one app id.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeededApp {
    hash: String,
    size: u64,
    /// Phase D: seeding priority weight + boost pool (for eviction decisions).
    #[serde(default)]
    weight: u32,
    #[serde(default)]
    boost: u64,
    /// короткий endpointId провайдера, у которого блоб был скачан (диагностика)
    #[serde(default)]
    provider: String,
    announce: AnnounceAppOwned,
}

/// Owned, serializable twin of AnnounceApp for the local state file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnnounceAppOwned {
    id: String,
    name: String,
    description: String,
    tags: Vec<String>,
    merkle: String,
    version: u32,
    hash: String,
    signature: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(default)]
    owner: String,
}

// ============================================================
//  iroh node
// ============================================================

struct Node {
    endpoint: Endpoint,
    store: FsStore,
    endpoint_id: String,
    _router: Router,
    /// Публичный SmartNet DHT bootstrap-узел (server mode). Хэндл нужен для
    /// телеметрии (/metrics: кол-во узлов в таблице маршрутизации).
    dht: Option<Dht>,
}

/// Load (or create + persist) a STABLE iroh secret key under <data_dir>/node.key
/// so the seeder keeps the SAME endpointId across restarts. Without this every
/// restart minted a fresh ephemeral identity, leaving stale duplicate entries
/// on the Network Map and resetting the node's reputation/score.
fn load_or_create_secret(data_dir: &str) -> iroh::SecretKey {
    let path = PathBuf::from(data_dir).join("node.key");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return iroh::SecretKey::from_bytes(&arr);
        }
    }
    let sk = iroh::SecretKey::generate();
    if std::fs::write(&path, sk.to_bytes()).is_ok() {
        tracing::info!("generated stable node key at {}", path.display());
    }
    sk
}

/// АСИНХРОННЫЙ резолв bootstrap-узлов Mainline DHT в IP:port (n0_mainline в
/// build() резолвит хосты СИНХРОННО — блокирует поток на таймаут DNS).
async fn resolve_dht_bootstrap() -> Vec<String> {
    const DEFAULTS: [&str; 4] = [
        "router.bittorrent.com:6881",
        "dht.transmissionbt.com:6881",
        "dht.libtorrent.org:25401",
        "relay.pkarr.org:6881",
    ];
    let mut handles = Vec::new();
    for h in DEFAULTS.iter().map(|s| s.to_string()) {
        handles.push(tokio::spawn(async move {
            if h.parse::<std::net::SocketAddr>().is_ok() {
                return vec![h];
            }
            match tokio::time::timeout(
                std::time::Duration::from_millis(1500),
                tokio::net::lookup_host(&h),
            )
            .await
            {
                Ok(Ok(addrs)) => addrs.filter(|a| a.is_ipv4()).map(|a| a.to_string()).collect(),
                _ => Vec::new(),
            }
        }));
    }
    let mut out = Vec::new();
    for handle in handles {
        if let Ok(v) = handle.await {
            out.extend(v);
        }
    }
    out.sort();
    out.dedup();
    out
}


async fn start_node(
    cfg: &Config,
    state: Arc<Mutex<HashMap<String, SeededApp>>>,
) -> Result<Node, String> {
    let blobs_dir = PathBuf::from(&cfg.data_dir).join("blobs");
    std::fs::create_dir_all(&blobs_dir).map_err(|e| e.to_string())?;

    // Garbage-collect unused blobs: every gc_interval the store keeps only the
    // blobs whose hash is in our live seeded set (seeded.json) and deletes the
    // rest (old versions / abandoned downloads). If we don't yet know our
    // keep-set (empty state) we ABORT the run so we never wipe blobs that are
    // about to be adopted from disk on the next cycle.
    let st = state.clone();
    let protect: ProtectCb = Arc::new(move |live: &mut HashSet<Hash>| {
        let st = st.clone();
        Box::pin(async move {
            let guard = st.lock().await;
            if guard.is_empty() {
                return ProtectOutcome::Abort;
            }
            for app in guard.values() {
                if let Ok(h) = app.hash.parse::<Hash>() {
                    live.insert(h);
                }
            }
            ProtectOutcome::Continue
        })
    });
    let mut options = Options::new(&blobs_dir);
    options.gc = Some(GcConfig {
        interval: Duration::from_secs(cfg.gc_interval_secs.max(60)),
        add_protected: Some(protect),
    });
    let store = FsStore::load_with_opts(blobs_dir.join("blobs.db"), options)
        .await
        .map_err(|e| e.to_string())?;

    let secret = load_or_create_secret(&cfg.data_dir);
    let mut builder = Endpoint::builder(presets::N0).secret_key(secret);
    if !cfg.relay_only {
        builder = builder.address_lookup(MdnsAddressLookup::builder());
    }
    // Bootstrap-узлы Mainline резолвим АСИНХРОННО заранее (n0_mainline build()
    // делает СИНХРОННЫЙ DNS и иначе блокировал бы поток на таймаут).
    let dht_boot = if cfg.dht_enabled {
        resolve_dht_bootstrap().await
    } else {
        Vec::new()
    };
    let endpoint = builder.bind().await.map_err(|e| e.to_string())?;
    let blobs = BlobsProtocol::new(&store, None);
    let router = Router::builder(endpoint.clone())
        .accept(iroh_blobs::ALPN, blobs)
        .spawn();
    let endpoint_id = endpoint.id().to_string();
    // Публичный SmartNet DHT bootstrap-узел: ОДИН Mainline-узел в SERVER mode на
    // фикс. UDP-порту (дефолтный порт Mainline = 6881, поэтому отдельный
    // address_lookup-узел НЕ поднимаем — иначе конфликт «Address already in use»).
    // Делает сидер достижимой точкой входа в DHT для клиентов/провайдеров за
    // NAT/закрытым egress — без n0/n1 и публичных BT-роутеров. Хэндл храним для
    // телеметрии (/metrics: routing_table_size).
    let dht = if cfg.dht_enabled {
        let mut sb = Dht::builder();
        sb.server_mode();
        sb.port(cfg.dht_port);
        sb.bootstrap(&dht_boot);
        match sb.build() {
            Ok(d) => {
                tracing::info!(
                    "SmartNet DHT bootstrap-узел: server mode, UDP-порт {} (откройте inbound UDP в фаерволе)",
                    cfg.dht_port
                );
                Some(d)
            }
            Err(e) => {
                tracing::warn!("DHT bootstrap-узел не запущен на :{} — {}", cfg.dht_port, e);
                None
            }
        }
    } else {
        None
    };
    Ok(Node {
        endpoint,
        store,
        endpoint_id,
        _router: router,
        dht,
    })
}

/// Download the tar blob `hash` from `provider` and read its content.json.
/// The blob stays content-addressed in the store and is re-served as-is.
///
/// Robustness: iroh's `download()` can return `Err` (e.g. a relay drop at the
/// tail of a transfer) even after the blob's bytes have fully landed in the
/// local store. So we treat a successful local EXPORT as the real source of
/// truth: if the blob is already complete on disk we seed it regardless of what
/// `download()` reported. This recovers apps that were fetched on an earlier
/// cycle but never got recorded because `download()` errored.
async fn fetch_app(
    node: &Node,
    _data_dir: &Path,
    provider_eid: &str,
    hash: &str,
) -> Result<(Manifest, u64), String> {
    let nid: EndpointId = provider_eid
        .parse()
        .map_err(|_| "invalid provider endpoint id".to_string())?;
    let h: Hash = hash.parse().map_err(|_| "invalid blob hash".to_string())?;

    // Fast path: blob already complete locally (possibly from a prior cycle
    // where download() reported failure). Serve it without re-fetching.
    match extract_manifest(node, h).await {
        Ok(res) => return Ok(res),
        Err(e) => tracing::debug!("local extract not ready for {}…: {}", &hash[..hash.len().min(12)], e),
    }

    // Fetch from the provider, retrying transient failures.
    //
    // IMPORTANT: iroh-blobs 0.103 `download().await` resolves to `Ok(())` even when
    // NOTHING transferred — its internal `complete()` only treats `Error`/`DownloadError`
    // items as failures and otherwise returns Ok when the provider's progress stream
    // ends (e.g. on `ProviderFailed`). So `Ok` is NOT proof the blob arrived. The
    // authoritative signal is the local blob STATUS after the call.
    let mut last_err = String::from("provider served no data");
    for attempt in 0..5u32 {
        if let Err(e) = node
            .store
            .downloader(&node.endpoint)
            .download(h, Some(nid))
            .await
        {
            last_err = format!("{:?}", e);
        }
        match node.store.blobs().status(h).await {
            Ok(BlobStatus::Complete { .. }) => break,
            Ok(BlobStatus::Partial { size }) => {
                last_err = format!(
                    "provider served only a partial blob ({} bytes) — the relay path is likely dropping bulk data",
                    size.unwrap_or(0)
                );
            }
            Ok(BlobStatus::NotFound) => {
                last_err =
                    "provider returned no data (blob absent on provider, or it refused to serve)"
                        .to_string();
            }
            Err(e) => last_err = format!("status check failed: {}", e),
        }
        tracing::debug!(
            "download attempt {}/5 from {}… not complete: {}",
            attempt + 1,
            &provider_eid[..provider_eid.len().min(10)],
            last_err
        );
        if attempt < 4 {
            tokio::time::sleep(Duration::from_millis(2000)).await;
        }
    }

    // Final completeness check: read the blob bytes straight from the store
    // (recovers data that landed on a prior cycle even if this cycle's status
    // raced). The PRECISE extract error is surfaced so the operator sees the real
    // reason instead of a misleading default when bytes are present but the
    // manifest can't be parsed.
    match extract_manifest(node, h).await {
        Ok(res) => Ok(res),
        // «blob absent» + ошибка чтения из пустого стора — шум; оставляем суть.
        Err(_) if last_err.contains("no data") => Err(describe_download_error(&last_err)),
        Err(e) => Err(describe_download_error(&format!("{}; {}", last_err, e))),
    }
}

/// Read the full blob bytes from the store (no fragile filesystem export — the
/// old `export()`-to-tmp-tar path could fail on a complete blob and mask the
/// real reason as "provider served no data") and parse the app Manifest out of
/// the in-memory tar. Returns (Manifest, blob_size) or a precise error.
async fn extract_manifest(node: &Node, h: Hash) -> Result<(Manifest, u64), String> {
    let bytes = node
        .store
        .blobs()
        .get_bytes(h)
        .await
        .map_err(|e| format!("blob not readable from store ({})", e))?;
    let size = bytes.len() as u64;
    match manifest_from_tar(&bytes) {
        Some(mut m) => {
            // Приватный dApp: подпись сделана над ПУСТЫМ description, а участникам
            // списка доступа нужен reveal-payload — реконструируем его из
            // access.json архива, чтобы ре-анонс сидера не «терял» метаданные.
            if m.private == Some(true) {
                if let Some(p) = reveal_payload_from_tar(&bytes) {
                    m.description = Some(p);
                }
            }
            Ok((m, size))
        }
        None => Err("content.json missing or unparseable in app archive".to_string()),
    }
}

/// Reveal-payload приватного dApp из access.json архива: `§P1§` + b64({m, k}).
/// m = зашифрованный компакт метаданных (privAnnounce), k = обёрнутые CEK по
/// адресам (wrappedKeys). Ключей у сидера нет — он лишь переносит шифртекст.
fn reveal_payload_from_tar(tar_bytes: &[u8]) -> Option<String> {
    use std::io::Read;
    let mut ar = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    for entry in ar.entries().ok()? {
        let mut entry = entry.ok()?;
        let path = entry.path().ok()?.to_string_lossy().to_string();
        if path != "access.json" && path != "./access.json" {
            continue;
        }
        let mut buf = String::new();
        entry.read_to_string(&mut buf).ok()?;
        let v: serde_json::Value = serde_json::from_str(&buf).ok()?;
        let announce = v.get("privAnnounce")?.as_str().unwrap_or("");
        let keys = v.get("wrappedKeys")?;
        if announce.is_empty() || !keys.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
            return None;
        }
        let payload = serde_json::json!({ "m": announce, "k": keys });
        return Some(format!("§P1§{}", BASE64_STANDARD.encode(payload.to_string())));
    }
    None
}

/// Parse the SmartNet Manifest from an in-memory app tar. Prefers the ROOT
/// `content.json` (the real manifest) and only falls back to a nested
/// `*/content.json` if no root one parses — apps that ship their own
/// `content.json` inside the bundle used to shadow the manifest (tar order),
/// which made the manifest unparseable and the fetch falsely "fail".
fn manifest_from_tar(tar_bytes: &[u8]) -> Option<Manifest> {
    use std::io::Read;
    let mut ar = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut fallback: Option<Manifest> = None;
    for entry in ar.entries().ok()? {
        let mut entry = entry.ok()?;
        let path = entry.path().ok()?.to_string_lossy().to_string();
        let is_root = path == "content.json" || path == "./content.json";
        let is_nested = path.ends_with("/content.json");
        if !is_root && !is_nested {
            continue;
        }
        let mut buf = String::new();
        if entry.read_to_string(&mut buf).is_err() {
            continue;
        }
        match serde_json::from_str::<Manifest>(&buf) {
            Ok(m) if is_root => return Some(m),
            Ok(m) if fallback.is_none() => fallback = Some(m),
            _ => {}
        }
    }
    fallback
}

/// Turn a raw iroh download error into a short, human-readable reason while
/// keeping the original text in brackets for deeper debugging.
fn describe_download_error(raw: &str) -> String {
    let l = raw.to_lowercase();
    let reason = if l.contains("not found") || l.contains("notfound") || l.contains("missing") || l.contains("absent") || l.contains("no data") {
        "blob not found on provider (provider GC'd it or announces a stale hash — provider must re-announce)"
    } else if l.contains("verif") || l.contains("mismatch") || l.contains("integrity") {
        "blob failed integrity check"
    } else if l.contains("timeout") || l.contains("timed out") {
        "timed out reaching provider (slow or no relay path)"
    } else if l.contains("io")
        || l.contains("connect")
        || l.contains("connection")
        || l.contains("dial")
        || l.contains("no addr")
        || l.contains("no known")
        || l.contains("resolve")
        || l.contains("unreachable")
    {
        "provider unreachable (offline, or no LAN/relay path to its endpoint)"
    } else {
        "download failed"
    };
    format!("{} [{}]", reason, raw)
}

#[allow(dead_code)]
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

// ============================================================
//  HTTP tracker client (blocking ureq on a worker thread)
// ============================================================

/// One-shot tracker connectivity probe printed as a table (`--check-trackers`).
async fn check_trackers(cfg: &Config) {
    println!("\nSmartNet seeder · tracker connectivity check\n");
    if cfg.trackers.is_empty() {
        println!("  (no trackers configured — add them under `trackers:` in config.yaml)\n");
        return;
    }
    println!("  {:<42}  {:>7}  {:>5}  {}", "TRACKER", "STATUS", "APPS", "DETAIL");
    let mut ok_count = 0usize;
    for tracker in &cfg.trackers {
        let t0 = Instant::now();
        let tk = tracker.clone();
        let res = tokio::task::spawn_blocking(move || {
            ureq::get(&format!("{}/apps", tk.trim_end_matches('/')))
                .timeout(Duration::from_secs(10))
                .call()
        })
        .await
        .unwrap();
        let ms = t0.elapsed().as_millis();
        match res {
            Ok(resp) => {
                let txt = resp.into_string().unwrap_or_default();
                match serde_json::from_str::<Vec<AppOut>>(&txt) {
                    Ok(v) => {
                        ok_count += 1;
                        let providers: usize = v.iter().map(|a| a.providers.len()).sum();
                        println!(
                            "  {:<42}  {:>7}  {:>5}  {} provider(s), {} ms",
                            tracker, "OK", v.len(), providers, ms
                        );
                    }
                    Err(e) => println!(
                        "  {:<42}  {:>7}  {:>5}  unparseable JSON: {}",
                        tracker, "BAD", "-", e
                    ),
                }
            }
            Err(ureq::Error::Status(code, _)) => {
                println!("  {:<42}  {:>7}  {:>5}  HTTP {}, {} ms", tracker, "HTTP", "-", code, ms)
            }
            Err(e) => println!("  {:<42}  {:>7}  {:>5}  {}", tracker, "DOWN", "-", e),
        }
    }
    println!("\n  {}/{} tracker(s) reachable.", ok_count, cfg.trackers.len());
    println!(
        "  If a tracker is OK but shows 0 apps while your desktop is online, the desktop\n  \
         is announcing to a DIFFERENT tracker — make the seeder's `trackers:` list match\n  \
         the desktop client's tracker list.\n"
    );
}

async fn tracker_apps(tracker: String) -> Vec<AppOut> {
    tokio::task::spawn_blocking(move || {
        let url = format!("{}/apps", tracker.trim_end_matches('/'));
        match ureq::get(&url).timeout(Duration::from_secs(15)).call() {
            Ok(resp) => {
                let txt = resp.into_string().unwrap_or_default();
                match serde_json::from_str::<Vec<AppOut>>(&txt) {
                    Ok(v) => {
                        tracing::info!("tracker {} → {} app(s) in directory", url, v.len());
                        v
                    }
                    Err(e) => {
                        tracing::warn!(
                            "tracker {} returned unparseable /apps ({}): {}",
                            url,
                            e,
                            txt.chars().take(160).collect::<String>()
                        );
                        Vec::new()
                    }
                }
            }
            Err(ureq::Error::Status(code, _)) => {
                tracing::warn!("tracker {} GET /apps → HTTP {}", url, code);
                Vec::new()
            }
            Err(e) => {
                tracing::warn!("tracker {} GET /apps unreachable: {}", url, e);
                Vec::new()
            }
        }
    })
    .await
    .unwrap_or_default()
}

/// Fetch the tracker's tombstone list (owner-deleted app ids). The seeder purges
/// these from its seed set so the store GC reclaims their blobs.
async fn tracker_deleted(tracker: String) -> Vec<String> {
    tokio::task::spawn_blocking(move || {
        let url = format!("{}/deleted", tracker.trim_end_matches('/'));
        match ureq::get(&url).timeout(Duration::from_secs(15)).call() {
            Ok(resp) => {
                let txt = resp.into_string().unwrap_or_default();
                serde_json::from_str::<Vec<String>>(&txt).unwrap_or_default()
            }
            Err(_) => Vec::new(),
        }
    })
    .await
    .unwrap_or_default()
}


async fn tracker_announce(tracker: String, body: String) -> bool {
    tokio::task::spawn_blocking(move || {
        let url = format!("{}/announce", tracker.trim_end_matches('/'));
        match ureq::post(&url)
            .timeout(Duration::from_secs(15))
            .set("Content-Type", "application/json")
            .send_string(&body)
        {
            Ok(_) => true,
            Err(ureq::Error::Status(code, _)) => {
                tracing::warn!("tracker {} POST /announce → HTTP {}", url, code);
                false
            }
            Err(e) => {
                tracing::warn!("tracker {} POST /announce unreachable: {}", url, e);
                false
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Build a signed heartbeat JSON body (Phase F). Returns None when no signing
/// secret (passphrase) is configured — an explicit reward_address alone cannot
/// sign, so the node earns no uptime credit until a passphrase is set.
fn build_heartbeat(secret: &str, active_app_ids: &[String]) -> Option<String> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    let sk = SecretKey::from_slice(&sha256(secret.as_bytes())).ok()?;
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let reward_address = address_from_secret(secret);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut ids: Vec<String> = active_app_ids.to_vec();
    ids.sort();
    let digest = sha256(format!("sthb|{}|{}|{}", reward_address, timestamp, ids.join(",")).as_bytes());
    let msg = secp256k1::Message::from_digest_slice(&digest).ok()?;
    let signature = hex::encode(secp.sign_ecdsa(&msg, &sk).serialize_compact());
    serde_json::to_string(&serde_json::json!({
        "timestamp": timestamp,
        "rewardAddress": reward_address,
        "activeAppIds": ids,
        "publicKey": hex::encode(pk.serialize()),
        "signature": signature,
    }))
    .ok()
}

async fn tracker_heartbeat(tracker: String, body: String) -> bool {
    tokio::task::spawn_blocking(move || {
        let url = format!("{}/seeder/heartbeat", tracker.trim_end_matches('/'));
        match ureq::post(&url)
            .timeout(Duration::from_secs(15))
            .set("Content-Type", "application/json")
            .send_string(&body)
        {
            Ok(_) => true,
            Err(ureq::Error::Status(code, _)) => {
                tracing::warn!("tracker {} POST /seeder/heartbeat → HTTP {}", url, code);
                false
            }
            Err(e) => {
                tracing::warn!("tracker {} heartbeat unreachable: {}", url, e);
                false
            }
        }
    })
    .await
    .unwrap_or(false)
}


/// Best-effort public IPv4 lookup (api.ipify.org) for auto-deriving the
/// Network Map metrics URL when the operator hasn't set one explicitly.
async fn detect_public_ip() -> Option<String> {
    tokio::task::spawn_blocking(|| {
        ureq::get("https://api.ipify.org")
            .timeout(Duration::from_secs(10))
            .call()
            .ok()
            .and_then(|r| r.into_string().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })
    .await
    .ok()
    .flatten()
}

// ============================================================
//  Local state persistence (survive restarts without re-downloading)
// ============================================================

fn state_path(cfg: &Config) -> PathBuf {
    PathBuf::from(&cfg.data_dir).join("seeded.json")
}

fn load_state(cfg: &Config) -> HashMap<String, SeededApp> {
    std::fs::read_to_string(state_path(cfg))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_state(cfg: &Config, state: &HashMap<String, SeededApp>) {
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = std::fs::write(state_path(cfg), json);
    }
}

// ============================================================
//  Metrics — contribution stats for VPS operators / reward ranking
// ============================================================

/// Per-app result of the most recent fetch attempt, surfaced on `/metrics`
/// (JSON `apps[]`) and the status page so provider health is visible without
/// reading VPS logs.
struct FetchEntry {
    name: String,
    provider: String, // short endpoint id of the provider we tried
    status: &'static str, // "ok" | "partial" | "notfound" | "error"
    detail: String,
    bytes: u64,
    updated: Instant,
}

/// Minimal JSON string escaper for embedding app names / error details.
fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// Minimal HTML escaper for the status page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Lock-free snapshot of this seeder's contribution, updated once per cycle
/// and exposed over HTTP (`/metrics` JSON + `/` status page) and the log.
struct Metrics {
    started: Instant,
    apps: AtomicUsize,
    bytes: AtomicU64,
    last_acks: AtomicUsize,
    storage_limit_gb: f64,
    endpoint_id: String,
    reward: String,
    trackers: usize,
    /// SmartNet DHT bootstrap-сервер: включён ли + порт + кол-во узлов в таблице.
    dht_enabled: bool,
    dht_port: u16,
    dht_nodes: AtomicU64,
    /// per-app last fetch result (id -> entry).
    fetch: std::sync::Mutex<HashMap<String, FetchEntry>>,
    /// медиа-сидинг мессенджера (None = выключен в конфиге)
    media: Option<Arc<media::MediaSeeder>>,
    media_storage_gb: f64,
}

impl Metrics {
    fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Record the most recent fetch outcome for one app.
    fn set_fetch(&self, id: &str, entry: FetchEntry) {
        if let Ok(mut g) = self.fetch.lock() {
            g.insert(id.to_string(), entry);
        }
    }

    /// Приложение больше не раздаём (tombstone / eviction) — убираем из таблицы,
    /// чтобы «APPS SEEDED» и список диагностики всегда совпадали.
    fn remove_fetch(&self, id: &str) {
        if let Ok(mut g) = self.fetch.lock() {
            g.remove(id);
        }
    }

    /// Строка медиа-статистики для JSON.
    fn media_json(&self) -> String {
        match &self.media {
            Some(m) => {
                let b = m.bytes.load(Ordering::Relaxed);
                format!(
                    "\"mediaEnabled\":true,\"mediaStorageGb\":{},\"mediaBytes\":{},\"mediaGb\":{:.4},\"mediaItems\":{},\"mediaEndpointId\":\"{}\",\"mediaFetchedOk\":{},\"mediaFetchedFail\":{},\"mediaEvicted\":{},\"mediaMaxFileBytes\":{}",
                    self.media_storage_gb,
                    b,
                    b as f64 / 1e9,
                    m.items.load(Ordering::Relaxed),
                    m.endpoint_id,
                    m.fetched_ok.load(Ordering::Relaxed),
                    m.fetched_fail.load(Ordering::Relaxed),
                    m.evicted.load(Ordering::Relaxed),
                    media::MEDIA_MAX_FILE_BYTES,
                )
            }
            None => "\"mediaEnabled\":false,\"mediaStorageGb\":0,\"mediaBytes\":0,\"mediaGb\":0,\"mediaItems\":0,\"mediaEndpointId\":\"\"".to_string(),
        }
    }

    fn json(&self) -> String {
        let bytes = self.bytes.load(Ordering::Relaxed);
        let apps_json = {
            let g = self.fetch.lock().unwrap();
            let mut ids: Vec<&String> = g.keys().collect();
            ids.sort();
            let parts: Vec<String> = ids
                .iter()
                .map(|id| {
                    let e = &g[*id];
                    format!(
                        "{{\"id\":\"{}\",\"name\":\"{}\",\"provider\":\"{}\",\"status\":\"{}\",\"lastFetchError\":{},\"bytes\":{},\"secondsAgo\":{}}}",
                        json_escape(id),
                        json_escape(&e.name),
                        json_escape(&e.provider),
                        e.status,
                        if e.detail.is_empty() {
                            "null".to_string()
                        } else {
                            format!("\"{}\"", json_escape(&e.detail))
                        },
                        e.bytes,
                        e.updated.elapsed().as_secs(),
                    )
                })
                .collect();
            format!("[{}]", parts.join(","))
        };
        format!(
            "{{\"version\":\"{}\",\"uptimeSecs\":{},\"appsSeeded\":{},\"bytesSeeded\":{},\"gbSeeded\":{:.4},\"storageLimitGb\":{},\"endpointId\":\"{}\",\"rewardAddress\":\"{}\",\"trackers\":{},\"lastAnnounceAcks\":{},\"dhtBootstrapServer\":{},\"dhtPort\":{},\"dhtNodes\":{},{},\"apps\":{}}}",
            VERSION,
            self.uptime_secs(),
            self.apps.load(Ordering::Relaxed),
            bytes,
            bytes as f64 / 1e9,
            self.storage_limit_gb,
            self.endpoint_id,
            self.reward,
            self.trackers,
            self.last_acks.load(Ordering::Relaxed),
            self.dht_enabled,
            self.dht_port,
            self.dht_nodes.load(Ordering::Relaxed),
            self.media_json(),
            apps_json,
        )
    }

    fn html(&self) -> String {
        let bytes = self.bytes.load(Ordering::Relaxed);
        let up = self.uptime_secs();
        let (d, h, m) = (up / 86400, (up % 86400) / 3600, (up % 3600) / 60);
        // per-app fetch diagnostics table
        let rows = {
            let g = self.fetch.lock().unwrap();
            let mut ids: Vec<&String> = g.keys().collect();
            ids.sort();
            if ids.is_empty() {
                "<tr><td colspan=4 style='color:#6c7086'>no fetch attempts yet</td></tr>".to_string()
            } else {
                ids.iter()
                    .map(|id| {
                        let e = &g[*id];
                        let color = match e.status {
                            "ok" => "#a6e3a1",
                            "partial" => "#f9e2af",
                            "notfound" => "#fab387",
                            _ => "#f38ba8",
                        };
                        let label = if e.name.is_empty() { (*id).clone() } else { e.name.clone() };
                        let detail = if e.detail.is_empty() {
                            format!("{:.1} KB", e.bytes as f64 / 1e3)
                        } else {
                            e.detail.clone()
                        };
                        format!(
                            "<tr><td>{}</td><td style='color:{};font-weight:700'>{}</td><td style='color:#6c7086'>{}…</td><td style='color:#6c7086'>{}</td></tr>",
                            html_escape(&label),
                            color,
                            e.status.to_uppercase(),
                            html_escape(&e.provider.chars().take(10).collect::<String>()),
                            html_escape(&detail),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("")
            }
        };
        let (media_row, media_ep) = match &self.media {
            Some(m) => (
                format!(
                    "{:.3} GB / {} GB · {} files",
                    m.bytes.load(Ordering::Relaxed) as f64 / 1e9,
                    self.media_storage_gb,
                    m.items.load(Ordering::Relaxed)
                ),
                m.endpoint_id.clone(),
            ),
            None => ("OFF (media_storage_gb: 0)".to_string(), "—".to_string()),
        };
        format!(
            "<!doctype html><html><head><meta charset=utf-8><title>SmartNet Seeder v{ver}</title>\
<meta name=viewport content='width=device-width,initial-scale=1'>\
<meta http-equiv=refresh content=15>\
<style>body{{background:#0b0e14;color:#cdd6f4;font:14px ui-monospace,monospace;margin:0;padding:40px}}\
h1{{color:#89b4fa;font-size:18px;letter-spacing:.1em}}\
h2{{color:#89b4fa;font-size:13px;letter-spacing:.08em;margin-top:36px;text-transform:uppercase}}\
.g{{display:grid;grid-template-columns:max-content 1fr;gap:8px 24px;margin-top:24px}}\
.k{{color:#6c7086;text-transform:uppercase;font-size:11px;letter-spacing:.08em}}\
.v{{color:#a6e3a1;font-weight:700}} a{{color:#89b4fa}}\
table{{border-collapse:collapse;margin-top:12px;width:100%;font-size:12px}}\
td,th{{text-align:left;padding:6px 14px 6px 0;border-bottom:1px solid #1e2233;vertical-align:top}}\
th{{color:#6c7086;text-transform:uppercase;font-size:10px;letter-spacing:.08em}}</style></head><body>\
<h1>// SMARTNET SEEDER v{ver}</h1><div class=g>\
<span class=k>uptime</span><span class=v>{}d {:02}h {:02}m</span>\
<span class=k>apps seeded</span><span class=v>{}</span>\
<span class=k>seeded</span><span class=v>{:.3} GB / {} GB</span>\
<span class=k>media</span><span class=v>{}</span>\
<span class=k>tracker acks</span><span class=v>{} / {}</span>\
<span class=k>reward addr</span><span class=v>{}</span>\
<span class=k>endpoint id</span><span class=v>{}</span>\
<span class=k>media endpoint</span><span class=v>{}</span>\
<span class=k>dht bootstrap</span><span class=v>{}</span>\
</div>\
<h2>// fetch diagnostics</h2>\
<table><tr><th>app</th><th>status</th><th>provider</th><th>detail / size</th></tr>{}</table>\
<p style='margin-top:24px;color:#6c7086'>auto-refresh 15s · JSON: <a href=/metrics>/metrics</a> · media: <a href=/media>/media</a></p></body></html>",
            d, h, m,
            self.apps.load(Ordering::Relaxed),
            bytes as f64 / 1e9,
            self.storage_limit_gb,
            html_escape(&media_row),
            self.last_acks.load(Ordering::Relaxed),
            self.trackers,
            if self.reward.is_empty() { "(none)" } else { &self.reward },
            self.endpoint_id,
            html_escape(&media_ep),
            if self.dht_enabled {
                format!("ON :{} · {} nodes", self.dht_port, self.dht_nodes.load(Ordering::Relaxed))
            } else {
                "OFF".to_string()
            },
            rows,
            ver = VERSION,
        )
    }
}

/// Минимальный HTTP/1.1 сервер без зависимостей: /metrics (JSON), статус-страница,
/// и медиа-API мессенджера (POST /media/announce, GET /media/has, GET /media).
async fn serve_metrics(metrics: Arc<Metrics>, port: u16) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("metrics endpoint disabled — bind :{} failed: {}", port, e);
            return;
        }
    };
    tracing::info!("metrics endpoint: http://0.0.0.0:{}/  (JSON at /metrics, media API at /media/*)", port);
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            // читаем заголовки целиком (+ тело по Content-Length, ≤ 64 КБ), с таймаутом
            let mut buf: Vec<u8> = Vec::with_capacity(2048);
            let mut tmp = [0u8; 2048];
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let (head_end, body_len) = loop {
                let n = match tokio::time::timeout_at(deadline, sock.read(&mut tmp)).await {
                    Ok(Ok(0)) | Err(_) => return,
                    Ok(Err(_)) => return,
                    Ok(Ok(n)) => n,
                };
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let cl = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if cl > 65_536 {
                        let _ = sock
                            .write_all(b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                            .await;
                        return;
                    }
                    break (pos + 4, cl);
                }
                if buf.len() > 16_384 {
                    return;
                }
            };
            while buf.len() < head_end + body_len {
                let n = match tokio::time::timeout_at(deadline, sock.read(&mut tmp)).await {
                    Ok(Ok(0)) | Err(_) => return,
                    Ok(Err(_)) => return,
                    Ok(Ok(n)) => n,
                };
                buf.extend_from_slice(&tmp[..n]);
            }
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let mut first = head.split_whitespace();
            let method = first.next().unwrap_or("GET").to_string();
            let target = first.next().unwrap_or("/").to_string();
            let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
            let body = String::from_utf8_lossy(&buf[head_end..head_end + body_len.min(buf.len() - head_end)]).to_string();

            let (status, ctype, out) = route(&metrics, &method, path, query, &body).await;
            let resp = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n{}",
                status,
                ctype,
                out.len(),
                out
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}

/// Значение query-параметра `key` (без percent-decoding — хэши/ID алфанумерные).
fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == key { Some(v) } else { None }
    })
}

async fn route(
    metrics: &Arc<Metrics>,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
) -> (&'static str, &'static str, String) {
    const JSON: &str = "application/json";
    if method == "OPTIONS" {
        return ("204 No Content", JSON, String::new());
    }
    match (method, path) {
        (_, "/metrics") => ("200 OK", JSON, metrics.json()),
        ("POST", "/media/announce") => {
            let Some(m) = &metrics.media else {
                return ("404 Not Found", JSON, "{\"ok\":false,\"error\":\"media seeding disabled on this seeder\"}".into());
            };
            let req: media::AnnounceIn = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => {
                    return ("400 Bad Request", JSON, format!("{{\"ok\":false,\"error\":\"bad json: {}\"}}", json_escape(&e.to_string())));
                }
            };
            match m.announce(req).await {
                Ok(st) => (
                    "200 OK",
                    JSON,
                    format!("{{\"ok\":true,\"status\":\"{}\",\"mediaEndpointId\":\"{}\"}}", st, m.endpoint_id),
                ),
                Err(e) => {
                    let code = if e.contains("queue full") { "429 Too Many Requests" } else { "400 Bad Request" };
                    (code, JSON, format!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&e)))
                }
            }
        }
        ("GET", "/media/has") => {
            let h = query_param(query, "h").unwrap_or("");
            if h.parse::<iroh_blobs::Hash>().is_err() {
                return ("400 Bad Request", JSON, "{\"ok\":false,\"error\":\"bad hash\"}".into());
            }
            let have = match &metrics.media {
                Some(m) => m.has(h).await,
                None => false,
            };
            (
                "200 OK",
                JSON,
                format!(
                    "{{\"have\":{},\"mediaEndpointId\":\"{}\"}}",
                    have,
                    metrics.media.as_ref().map(|m| m.endpoint_id.as_str()).unwrap_or("")
                ),
            )
        }
        ("GET", "/media") => {
            let Some(m) = &metrics.media else {
                return ("200 OK", JSON, "{\"enabled\":false,\"items\":[]}".into());
            };
            let items: Vec<String> = m
                .list(500)
                .await
                .into_iter()
                .map(|(h, it)| {
                    format!(
                        "{{\"hash\":\"{}\",\"size\":{},\"ts\":{},\"provider\":\"{}\"}}",
                        json_escape(&h),
                        it.size,
                        it.ts,
                        json_escape(&it.provider)
                    )
                })
                .collect();
            (
                "200 OK",
                JSON,
                format!(
                    "{{\"enabled\":true,\"mediaEndpointId\":\"{}\",\"bytes\":{},\"limitBytes\":{},\"items\":[{}]}}",
                    m.endpoint_id,
                    m.bytes.load(Ordering::Relaxed),
                    m.limit,
                    items.join(",")
                ),
            )
        }
        _ => ("200 OK", "text/html; charset=utf-8", metrics.html()),
    }
}

/// Print a one-line contribution summary to the log every N seconds.
async fn metrics_logger(metrics: Arc<Metrics>, interval_secs: u64) {
    let interval = Duration::from_secs(interval_secs.max(30));
    loop {
        tokio::time::sleep(interval).await;
        let bytes = metrics.bytes.load(Ordering::Relaxed);
        let up = metrics.uptime_secs();
        let media_s = match &metrics.media {
            Some(m) => format!(
                " · media {} file(s) {:.3}/{} GB",
                m.items.load(Ordering::Relaxed),
                m.bytes.load(Ordering::Relaxed) as f64 / 1e9,
                metrics.media_storage_gb
            ),
            None => String::new(),
        };
        tracing::info!(
            "STATS · v{} · uptime {}h{:02}m · seeding {} app(s) · {:.3}/{} GB · last acks {}/{}{}",
            VERSION,
            up / 3600,
            (up % 3600) / 60,
            metrics.apps.load(Ordering::Relaxed),
            bytes as f64 / 1e9,
            metrics.storage_limit_gb,
            metrics.last_acks.load(Ordering::Relaxed),
            metrics.trackers,
            media_s,
        );
    }
}

// ============================================================
//  Main seeding loop
// ============================================================

#[tokio::main]
async fn main() {
    // Подхватываем настройки из `.env` (если файл рядом с бинарником или в текущей
    // директории). Удобно для VPS: одна правка `.env` вместо ручного экспорта.
    // Отсутствие файла — не ошибка: значения всё ещё можно задать через shell
    // или systemd `EnvironmentFile=`.
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "smartnet_seeder=info".into()),
        )
        .init();

    let cfg_path = std::env::args()
        .nth(1)
        .filter(|a| !a.starts_with('-'))
        .unwrap_or_else(|| "config.yaml".to_string());
    let cfg = load_or_init_config(Path::new(&cfg_path));
    std::fs::create_dir_all(&cfg.data_dir).ok();

    // `--check-trackers`: one-shot connectivity probe of every configured tracker,
    // print a table and exit (handy when first wiring up a VPS).
    if std::env::args().any(|a| a == "--check-trackers") {
        check_trackers(&cfg).await;
        return;
    }

    let reward = cfg.resolved_reward_address();
    let limit = cfg.storage_limit_bytes();
    let incentivized = incentivized_enabled();
    // Official Repository: скан он-чейн реестров при старте + раз в 24ч.
    spawn_official_scanner();
    tracing::info!(
        "incentivized seeding: {} (toggle with ENABLE_INCENTIVIZED_SEEDING)",
        if incentivized { "ON — priority eviction active" } else { "OFF — standard P2P seeding" }
    );
    tracing::info!(
        "SmartNet seeder v{} starting · data_dir={} · budget={:.1} GB · media={:.1} GB · trackers={} · reward={}",
        VERSION,
        cfg.data_dir,
        cfg.storage_limit_gb,
        cfg.media_storage_gb,
        cfg.trackers.len(),
        if reward.is_empty() { "(none)" } else { &reward }
    );
    tracing::info!("configured trackers: {}", cfg.trackers.join(", "));
    if cfg.trackers.is_empty() {
        tracing::warn!(
            "no trackers configured — the seeder cannot learn the app directory. \
             Set `trackers:` in {} to the SAME URLs your desktop client announces to.",
            cfg_path
        );
    }

    // restore previously-seeded apps (blobs persist in the FsStore). Built BEFORE
    // the node so the store's GC protect-callback can read this live keep-set.
    let state: Arc<Mutex<HashMap<String, SeededApp>>> = Arc::new(Mutex::new(load_state(&cfg)));
    {
        let total: u64 = state.lock().await.values().map(|s| s.size).sum();
        tracing::info!(
            "restored {} app(s) from state ({:.1} MB used)",
            state.lock().await.len(),
            total as f64 / 1e6
        );
    }

    let node = match start_node(&cfg, state.clone()).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("failed to start iroh node: {}", e);
            std::process::exit(1);
        }
    };
    tracing::info!("iroh endpoint id: {}", node.endpoint_id);

    // Phase F: signed availability heartbeat every 5 minutes to all trackers.
    {
        let secret = cfg.reward_passphrase.trim().to_string();
        let trackers = cfg.trackers.clone();
        let hb_state = state.clone();
        if secret.is_empty() {
            tracing::warn!("no reward_passphrase set — heartbeats disabled (no uptime credit)");
        } else {
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(300));
                loop {
                    tick.tick().await;
                    let ids: Vec<String> = hb_state.lock().await.keys().cloned().collect();
                    if let Some(body) = build_heartbeat(&secret, &ids) {
                        for tk in &trackers {
                            let _ = tracker_heartbeat(tk.clone(), body.clone()).await;
                        }
                    }
                }
            });
        }
    }

    let node_label = if reward.is_empty() {
        format!("seeder:{}", &node.endpoint_id[..node.endpoint_id.len().min(8)])
    } else {
        reward.clone()
    };
    let poll = Duration::from_secs(cfg.poll_interval_secs.max(5));

    // Resolve the public /metrics URL advertised to the Network Map: explicit
    // config wins, else auto-detect the public IP and pair it with metrics_port.
    let metrics_url = if !cfg.public_metrics_url.trim().is_empty() {
        let u = cfg.public_metrics_url.trim().to_string();
        tracing::info!("metrics URL (configured): {}", u);
        u
    } else if cfg.metrics_port > 0 {
        match detect_public_ip().await {
            Some(ip) => {
                let u = format!("http://{}:{}/metrics", ip, cfg.metrics_port);
                tracing::info!("metrics URL (auto-detected): {}", u);
                u
            }
            None => {
                tracing::warn!("could not auto-detect public IP — not advertising metrics URL");
                String::new()
            }
        }
    } else {
        String::new()
    };

    // DHT bootstrap addr advertised to trackers (host of metrics_url + dht_port)
    // so clients auto-discover this seeder via GET /seeders-dht.
    let seeder_dht = if cfg.dht_enabled && !metrics_url.is_empty() {
        let host = metrics_url
            .strip_prefix("http://")
            .or_else(|| metrics_url.strip_prefix("https://"))
            .unwrap_or(&metrics_url)
            .split(['/', ':'])
            .next()
            .unwrap_or("")
            .to_string();
        if host.is_empty() {
            String::new()
        } else {
            format!("{}:{}", host, cfg.dht_port)
        }
    } else {
        String::new()
    };
    if !seeder_dht.is_empty() {
        tracing::info!("advertising DHT seeder addr: {}", seeder_dht);
    }
    let (init_apps, init_bytes) = {
        let st = state.lock().await;
        (st.len(), st.values().map(|s| s.size).sum::<u64>())
    };
    // Медиа-сидинг мессенджера: отдельный store/endpoint, только если задан бюджет.
    let media_seeder = if cfg.media_storage_gb > 0.0 {
        if cfg.media_storage_gb < 0.1 {
            tracing::warn!("media_storage_gb={} too small — effective media budget is 0.1 GB", cfg.media_storage_gb);
        }
        match media::MediaSeeder::start(&cfg.data_dir, cfg.media_storage_gb, cfg.relay_only).await {
            Ok(m) => Some(m),
            Err(e) => {
                tracing::error!("media seeding disabled — failed to start media node: {}", e);
                None
            }
        }
    } else {
        tracing::info!("media seeding OFF (set media_storage_gb: <GB> in config.yaml to enable)");
        None
    };
    let metrics = Arc::new(Metrics {
        started: Instant::now(),
        apps: AtomicUsize::new(init_apps),
        bytes: AtomicU64::new(init_bytes),
        last_acks: AtomicUsize::new(0),
        storage_limit_gb: cfg.storage_limit_gb,
        endpoint_id: node.endpoint_id.clone(),
        reward: reward.clone(),
        trackers: cfg.trackers.len(),
        dht_enabled: cfg.dht_enabled,
        dht_port: cfg.dht_port,
        dht_nodes: AtomicU64::new(0),
        fetch: std::sync::Mutex::new(HashMap::new()),
        media: media_seeder,
        media_storage_gb: cfg.media_storage_gb,
    });
    // Таблица диагностики сразу содержит ВСЕ восстановленные с диска приложения —
    // иначе «APPS SEEDED: 20», а в списке лишь те, что качались в этом запуске.
    {
        let st = state.lock().await;
        for (id, s) in st.iter() {
            metrics.set_fetch(
                id,
                FetchEntry {
                    name: s.announce.name.clone(),
                    provider: if s.provider.is_empty() { "(disk)".to_string() } else { s.provider.clone() },
                    status: "ok",
                    detail: String::new(),
                    bytes: s.size,
                    updated: Instant::now(),
                },
            );
        }
    }
    // Телеметрия DHT bootstrap-узла: каждые 12с пишем размер таблицы маршрутизации.
    if let Some(d) = node.dht.clone() {
        let m = metrics.clone();
        tokio::spawn(async move {
            let _ = d.bootstrapped().await;
            loop {
                if let Ok(info) = d.info().await {
                    m.dht_nodes.store(info.routing_table_size() as u64, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_secs(12)).await;
            }
        });
    }
    if cfg.metrics_port > 0 {
        tokio::spawn(serve_metrics(metrics.clone(), cfg.metrics_port));
    }
    tokio::spawn(metrics_logger(metrics.clone(), cfg.metrics_interval_secs));

    // Wait for iroh to come online (connected to a home relay) before the first
    // seeding cycle. Without this, the very first downloads fire while the relay
    // handshake is still in progress and fail with Error::Io. Bounded by a
    // timeout so we never hang if relays are unreachable — retries recover later.
    match tokio::time::timeout(Duration::from_secs(20), node.endpoint.online()).await {
        Ok(_) => tracing::info!("iroh online — home relay connected; starting seeding loop"),
        Err(_) => {
            tracing::warn!("iroh not online after 20s (relays unreachable?) — starting anyway; downloads will retry")
        }
    }

    // Экспоненциальный backoff для целей, падающих много циклов подряд:
    // 1-я неудача → пауза 5 мин, 2-я → 15 мин, 3-я и далее → 60 мин (max).
    // Смена целевого хэша (переопубликация) сбрасывает backoff — новый блоб
    // пробуем сразу. Защищает CPU/сеть от бесплодных download-штормов каждые
    // 30 секунд (QUIC/relay-диалы к провайдерам, у которых блоба нет).
    let mut fetch_backoff: HashMap<String, (String, u32, Instant)> = HashMap::new();

    loop {
        // 0) honor owner-signed deletions: gather tombstoned ids from the
        //    trackers and purge them from our seed set. Dropping them from the
        //    keep-set lets the store GC reclaim their blobs and we stop announcing.
        let mut deleted: HashSet<String> = HashSet::new();
        for tracker in &cfg.trackers {
            for id in tracker_deleted(tracker.clone()).await {
                deleted.insert(id);
            }
        }
        if !deleted.is_empty() {
            let mut removed = 0usize;
            {
                let mut st = state.lock().await;
                for id in &deleted {
                    if st.remove(id).is_some() {
                        metrics.remove_fetch(id);
                        removed += 1;
                    }
                }
                if removed > 0 {
                    save_state(&cfg, &st);
                }
            }
            if removed > 0 {
                let n = state.lock().await.len();
                metrics.apps.store(n, Ordering::Relaxed);
                tracing::info!("purged {} owner-deleted app(s) from seed set", removed);
            }
        }

        // 1) learn the directory: for each app id collect ALL provider endpoints
        //    serving the best (highest-version) blob, carrying the tracker's
        //    priority weight / boost pool (Phase D). Multiple providers are kept
        //    so a dead/empty provider can be skipped in favor of a live one.
        let mut best: HashMap<String, Target> = HashMap::new();
        // Phase G: макс. остаток оплаченного окна и факт оплаты по каждому app
        // (берём максимум по трекерам, чтобы не удалить приложение, которое хотя
        // бы один трекер считает ещё активным).
        let mut remaining: HashMap<String, u64> = HashMap::new();
        let mut paid_seen: HashSet<String> = HashSet::new();
        for tracker in &cfg.trackers {
            for app in tracker_apps(tracker.clone()).await {
                if deleted.contains(&app.id) {
                    continue; // never re-download a tombstoned app
                }
                if app.paid {
                    paid_seen.insert(app.id.clone());
                }
                let r = remaining.entry(app.id.clone()).or_insert(0);
                *r = (*r).max(app.seconds_remaining);
                for p in &app.providers {
                    if p.hash.is_empty() || p.endpoint_id == node.endpoint_id {
                        continue; // skip empties and our own announces
                    }
                    // ВАЖНО: только СОБСТВЕННАЯ версия провайдера (p.version).
                    // Раньше здесь было p.version.max(app.version) — из-за этого
                    // провайдер со СТАРЫМ хэшем «наследовал» новейшую версию
                    // приложения, его устаревший блоб становился целью, а нода с
                    // настоящим новым блобом отбрасывалась (ver==entry.ver при
                    // другом hash). Итог: вечный «blob absent on provider».
                    let ver = p.version;
                    let entry = best.entry(app.id.clone()).or_insert(Target {
                        eids: Vec::new(),
                        hash: p.hash.clone(),
                        ver: 0,
                        name: app.name.clone(),
                        weight: app.priority_weight,
                        boost: app.boost_pool,
                    });
                    entry.weight = app.priority_weight;
                    entry.boost = app.boost_pool;
                    if ver > entry.ver {
                        // newer version supersedes — reset the provider set.
                        entry.ver = ver;
                        entry.hash = p.hash.clone();
                        entry.name = app.name.clone();
                        entry.eids = vec![p.endpoint_id.clone()];
                    } else if ver == entry.ver && p.hash == entry.hash {
                        // another provider for the SAME blob — add as fallback.
                        if !entry.eids.contains(&p.endpoint_id) {
                            entry.eids.push(p.endpoint_id.clone());
                        }
                    }
                }
            }
        }

        // Highest seeding priority first (boosted dApps win scarce disk budget).
        let mut targets: Vec<(String, Target)> = best.into_iter().collect();
        targets.sort_by(|a, b| b.1.weight.cmp(&a.1.weight));

        // 1b) Phase G — headless disk hygiene: когда занятость диска > порога (90%),
        //     освобождаем место, удаляя приложения с ЗАВЕРШЁННЫМ оплаченным периодом
        //     (paid && secondsRemaining==0). Активные (оплачиваемые) и приложения,
        //     статус которых трекеры сейчас не подтверждают, НЕ трогаем.
        if incentivized {
            let evict_threshold = (limit as f64 * SEEDER_EVICT_FILL_RATIO) as u64;
            let mut used_now: u64 = state.lock().await.values().map(|s| s.size).sum();
            if used_now > evict_threshold {
                // кандидаты: наши приложения, которые трекер знает как оплаченные,
                // но их окно истекло (remaining==0). Наименьший вес — первым.
                let mut candidates: Vec<(String, u64, u32)> = {
                    let st = state.lock().await;
                    st.iter()
                        .filter(|(id, _)| {
                            paid_seen.contains(*id) && remaining.get(*id).copied().unwrap_or(0) == 0
                        })
                        .map(|(id, s)| (id.clone(), s.size, s.weight))
                        .collect()
                };
                candidates.sort_by(|a, b| a.2.cmp(&b.2).then(b.1.cmp(&a.1)));
                let mut freed = 0u64;
                let mut removed = 0usize;
                {
                    let mut st = state.lock().await;
                    for (id, sz, _) in candidates {
                        if used_now <= evict_threshold {
                            break;
                        }
                        if st.remove(&id).is_some() {
                            metrics.remove_fetch(&id);
                            used_now = used_now.saturating_sub(sz);
                            freed += sz;
                            removed += 1;
                            tracing::info!(
                                "expired-paid evict {}… ({:.1} MB) — paid seeding window ended, disk >90%",
                                &id[..id.len().min(10)],
                                sz as f64 / 1e6
                            );
                        }
                    }
                    if removed > 0 {
                        save_state(&cfg, &st);
                    }
                }
                if removed > 0 {
                    let n = state.lock().await.len();
                    metrics.apps.store(n, Ordering::Relaxed);
                    tracing::info!(
                        "freed {:.1} MB by dropping {} expired-paid app(s) (disk was >{:.0}% full)",
                        freed as f64 / 1e6,
                        removed,
                        SEEDER_EVICT_FILL_RATIO * 100.0
                    );
                }
            }
        }

        // 2) download new / changed apps within the storage budget
        let mut used: u64 = state.lock().await.values().map(|s| s.size).sum();
        for (id, tgt) in &targets {
            let (hash, dir_name) = (&tgt.hash, &tgt.name);
            {
                let st = state.lock().await;
                if st.get(id).map(|s| &s.hash) == Some(hash) {
                    continue; // already seeding this exact blob
                }
            }
            // Backoff: эта цель недавно падала — пропускаем до конца паузы.
            if let Some((bh, fails, until)) = fetch_backoff.get(id) {
                if bh == hash && Instant::now() < *until {
                    tracing::debug!(
                        "backoff {}… — {} fail(s), retry in {}s",
                        &id[..id.len().min(10)],
                        fails,
                        until.saturating_duration_since(Instant::now()).as_secs()
                    );
                    continue;
                }
            }
            let is_new = { !state.lock().await.contains_key(id) };
            if is_new && used >= limit {
                // Over budget. With incentivized seeding ON, a BOOSTED app may
                // evict the lowest-weight UNBOOSTED app to claim the space.
                let mut evicted = false;
                if incentivized && tgt.boost > 0 {
                    let mut st = state.lock().await;
                    if let Some((evict_id, sz)) = st
                        .iter()
                        .filter(|(_, s)| s.boost == 0)
                        .min_by_key(|(_, s)| s.weight)
                        .map(|(k, s)| (k.clone(), s.size))
                    {
                        st.remove(&evict_id);
                        metrics.remove_fetch(&evict_id);
                        used = used.saturating_sub(sz);
                        save_state(&cfg, &st);
                        tracing::info!(
                            "evicted unboosted {}… ({:.1} KB) for boosted {}…",
                            &evict_id[..evict_id.len().min(10)],
                            sz as f64 / 1e3,
                            &id[..id.len().min(10)]
                        );
                        evicted = true;
                    }
                }
                if !evicted {
                    continue; // no eviction possible — skip this new app
                }
            }
            // Try each candidate provider in turn until one actually delivers
            // the blob. A provider may announce an app it no longer has (GC'd /
            // restarted), so we must not give up after the first dead one.
            let mut fetched: Option<(Manifest, u64, String)> = None;
            let mut last_e = String::from("no providers serve this app");
            let mut last_provider = String::new();
            for eid in &tgt.eids {
                let provider_short: String = eid.chars().take(16).collect();
                match fetch_app(&node, Path::new(&cfg.data_dir), eid, hash).await {
                    Ok((m, size)) => {
                        fetched = Some((m, size, provider_short));
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(
                            "provider {}… has no usable blob for {}…: {}",
                            &eid[..eid.len().min(10)],
                            &id[..id.len().min(10)],
                            e
                        );
                        last_e = e;
                        last_provider = provider_short;
                    }
                }
            }
            match fetched {
                Some((m, size, provider_short)) => {
                    fetch_backoff.remove(id);
                    metrics.set_fetch(
                        id,
                        FetchEntry {
                            name: m.name.clone(),
                            provider: provider_short.clone(),
                            status: "ok",
                            detail: String::new(),
                            bytes: size,
                            updated: Instant::now(),
                        },
                    );
                    let announce = AnnounceAppOwned {
                        id: m.id.clone(),
                        name: m.name.clone(),
                        description: m.description.clone().unwrap_or_default(),
                        tags: m.tags.clone(),
                        merkle: m.merkle.clone(),
                        version: m.version.unwrap_or(1),
                        hash: hash.clone(),
                        signature: m.signature.clone(),
                        public_key: m.public_key.clone(),
                        owner: m.owner.clone(),
                    };
                    let mut st = state.lock().await;
                    if let Some(old) = st.get(id) {
                        used = used.saturating_sub(old.size);
                    }
                    used = used.saturating_add(size);
                    st.insert(
                        id.clone(),
                        SeededApp {
                            hash: hash.clone(),
                            size,
                            weight: tgt.weight,
                            boost: tgt.boost,
                            provider: provider_short.clone(),
                            announce,
                        },
                    );
                    tracing::info!(
                        "seeding {} v{} ({:.1} KB) — {} app(s), {:.1}/{:.1} MB",
                        id,
                        m.version.unwrap_or(1),
                        size as f64 / 1e3,
                        st.len(),
                        used as f64 / 1e6,
                        limit as f64 / 1e6
                    );
                    save_state(&cfg, &st);
                }
                None => {
                    // Наращиваем backoff (5 → 15 → 60 мин, max 60); смена хэша
                    // цели обнуляет счётчик — новый блоб пробуем без задержки.
                    let fails = match fetch_backoff.get(id) {
                        Some((bh, f, _)) if bh == hash => f + 1,
                        _ => 1,
                    };
                    let pause_min: u64 = match fails {
                        1 => 5,
                        2 => 15,
                        _ => 60,
                    };
                    fetch_backoff.insert(
                        id.clone(),
                        (
                            hash.clone(),
                            fails,
                            Instant::now() + Duration::from_secs(pause_min * 60),
                        ),
                    );
                    let le = last_e.to_lowercase();
                    let status = if le.contains("partial") {
                        "partial"
                    } else if le.contains("no data")
                        || le.contains("not found")
                        || le.contains("notfound")
                        || le.contains("absent")
                    {
                        "notfound"
                    } else {
                        "error"
                    };
                    let nm = if dir_name.is_empty() { id.clone() } else { dir_name.clone() };
                    metrics.set_fetch(
                        id,
                        FetchEntry {
                            name: nm,
                            provider: last_provider.clone(),
                            status,
                            detail: last_e.clone(),
                            bytes: 0,
                            updated: Instant::now(),
                        },
                    );
                    tracing::warn!(
                        "skip {}… — no provider delivered the blob ({} tried): {}; backoff {} min (fail #{})",
                        &id[..id.len().min(10)],
                        tgt.eids.len(),
                        last_e,
                        pause_min,
                        fails
                    )
                }
            }
        }

        // 3) announce everything we serve to every tracker
        let apps: Vec<AnnounceApp> = state
            .lock()
            .await
            .values()
            .map(|s| AnnounceApp {
                id: s.announce.id.clone(),
                name: s.announce.name.clone(),
                description: s.announce.description.clone(),
                tags: s.announce.tags.clone(),
                merkle: s.announce.merkle.clone(),
                version: s.announce.version,
                hash: s.announce.hash.clone(),
                signature: s.announce.signature.clone(),
                public_key: s.announce.public_key.clone(),
                owner: s.announce.owner.clone(),
            })
            .collect();
        // 3) heartbeat-announce to every tracker. We ALWAYS announce — even
        //    with zero seeded apps — so the tracker registers our metricsUrl
        //    and we appear on the public Network Map as soon as we're online.
        let had_apps = !apps.is_empty();
        let req = AnnounceReq {
            node: node_label.clone(),
            endpoint_id: node.endpoint_id.clone(),
            metrics_url: metrics_url.clone(),
            apps,
            seeder_dht: seeder_dht.clone(),
        };
        if let Ok(body) = serde_json::to_string(&req) {
            let mut acks: usize = 0;
            for tracker in &cfg.trackers {
                if tracker_announce(tracker.clone(), body.clone()).await {
                    acks += 1;
                }
            }
            metrics.last_acks.store(acks, Ordering::Relaxed);
            tracing::info!(
                "heartbeat: announced {} app(s) to {}/{} tracker(s)",
                req.apps.len(),
                acks,
                cfg.trackers.len()
            );
        }
        if !had_apps {
            if targets.is_empty() {
                tracing::info!("nothing to seed yet — waiting for the directory to populate");
            } else {
                tracing::info!(
                    "directory lists {} app(s) but none are reachable yet — providers may be offline; will retry next cycle",
                    targets.len()
                );
            }
        }

        // refresh contribution metrics for the HTTP endpoint + periodic log
        {
            let st = state.lock().await;
            metrics.apps.store(st.len(), Ordering::Relaxed);
            metrics
                .bytes
                .store(st.values().map(|s| s.size).sum::<u64>(), Ordering::Relaxed);
        }

        tokio::time::sleep(poll).await;
    }
}
