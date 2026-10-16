// Author: TechnoL0g
// Project: SmartNet Core
// Date: 2026-06-20
/*
 * SmartNet // smartnet-seeder — messenger media seeding
 *
 *   Медиа чатов Netfory (фото/аудио/файлы/видео) живут в iroh-blobs у авторов
 *   и у тех, кто уже скачал. Когда автор офлайн, медиа недоступно. Headless-
 *   сидер закрывает эту дыру: клиент, отправив медиа, POST-ит {hash, свой
 *   медиа-endpoint} на `/media/announce`, сидер СРАЗУ скачивает блоб и раздаёт
 *   его 24/7 — получатели видят медиа «мгновенно», как в обычном мессенджере.
 *
 *   Изоляция от dApp-хранилища: ОТДЕЛЬНЫЙ FsStore (<data_dir>/media-blobs),
 *   ОТДЕЛЬНЫЙ iroh-endpoint (media.key) и отдельный бюджет `media_storage_gb`
 *   (0 = выключено). При заполнении >90% удаляются 50% самых старых медиа.
 */

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint::presets;
use iroh::{protocol::Router, Endpoint, EndpointId};
use iroh_blobs::api::proto::BlobStatus;
use iroh_blobs::store::fs::options::Options;
use iroh_blobs::store::{GcConfig, ProtectCb, ProtectOutcome};
use iroh_blobs::{store::fs::FsStore, BlobsProtocol, Hash};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};

/// Порог заполнения медиа-бюджета, после которого запускается уборка.
pub const MEDIA_EVICT_FILL_RATIO: f64 = 0.90;
/// Доля занятых байт, освобождаемая уборкой (самые старые — первыми).
pub const MEDIA_EVICT_DROP_RATIO: f64 = 0.50;
/// Потолок одного медиа-файла — как MAX_VIDEO_BYTES у клиента Netfory.
pub const MEDIA_MAX_FILE_BYTES: u64 = 500 * 1024 * 1024;
const QUEUE_CAP: usize = 2048;
const PARALLEL_FETCHES: usize = 3;
const FETCH_ATTEMPTS: u32 = 4;
const MEDIA_GC_SECS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaItem {
    pub size: u64,
    /// unix-секунды приёма (порядок уборки: старые первыми)
    pub ts: u64,
    #[serde(default)]
    pub provider: String,
}

/// Тело `POST /media/announce` — зеркало медиа-конверта чата (`h`,`n`,`s`) +
/// дополнительные провайдеры `p` (bootstrap-ноды группы / Provider Registry).
#[derive(Debug, Deserialize)]
pub struct AnnounceIn {
    pub h: String,
    pub n: String,
    #[serde(default)]
    pub s: u64,
    #[serde(default)]
    pub p: Vec<String>,
}

struct Job {
    hash: Hash,
    providers: Vec<EndpointId>,
    size_hint: u64,
}

pub struct MediaSeeder {
    pub endpoint_id: String,
    pub limit: u64,
    store: FsStore,
    endpoint: Endpoint,
    _router: Router,
    state_path: PathBuf,
    state: Arc<Mutex<HashMap<String, MediaItem>>>,
    tx: mpsc::Sender<Job>,
    pending: std::sync::Mutex<HashSet<String>>,
    pub bytes: AtomicU64,
    pub items: AtomicU64,
    pub fetched_ok: AtomicU64,
    pub fetched_fail: AtomicU64,
    pub evicted: AtomicU64,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn load_or_create_secret(path: &PathBuf) -> iroh::SecretKey {
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return iroh::SecretKey::from_bytes(&arr);
        }
    }
    let sk = iroh::SecretKey::generate();
    let _ = std::fs::write(path, sk.to_bytes());
    sk
}

impl MediaSeeder {
    /// Поднять изолированный медиа-узел: отдельный store + endpoint + воркер.
    pub async fn start(
        data_dir: &str,
        limit_gb: f64,
        relay_only: bool,
    ) -> Result<Arc<MediaSeeder>, String> {
        let root = PathBuf::from(data_dir).join("media-blobs");
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let state_path = PathBuf::from(data_dir).join("media.json");
        let loaded: HashMap<String, MediaItem> = std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let init_bytes: u64 = loaded.values().map(|m| m.size).sum();
        let init_items = loaded.len() as u64;
        let state = Arc::new(Mutex::new(loaded));

        // GC: живут только блобы из media.json; всё остальное (недокачанные /
        // вычищенные уборкой) удаляется. Пустое состояние — GC работает штатно:
        // у медиа нет «усыновления с диска», как у dApp.
        let st = state.clone();
        let protect: ProtectCb = Arc::new(move |live: &mut HashSet<Hash>| {
            let st = st.clone();
            Box::pin(async move {
                for h in st.lock().await.keys() {
                    if let Ok(h) = h.parse::<Hash>() {
                        live.insert(h);
                    }
                }
                ProtectOutcome::Continue
            })
        });
        let mut options = Options::new(&root);
        options.gc = Some(GcConfig {
            interval: Duration::from_secs(MEDIA_GC_SECS),
            add_protected: Some(protect),
        });
        let store = FsStore::load_with_opts(root.join("blobs.db"), options)
            .await
            .map_err(|e| e.to_string())?;

        let secret = load_or_create_secret(&PathBuf::from(data_dir).join("media.key"));
        let mut builder = Endpoint::builder(presets::N0).secret_key(secret);
        if !relay_only {
            builder = builder.address_lookup(MdnsAddressLookup::builder());
        }
        let endpoint = builder.bind().await.map_err(|e| e.to_string())?;
        let blobs = BlobsProtocol::new(&store, None);
        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        let endpoint_id = endpoint.id().to_string();

        let (tx, rx) = mpsc::channel::<Job>(QUEUE_CAP);
        let me = Arc::new(MediaSeeder {
            endpoint_id,
            limit: (limit_gb.max(0.1) * 1_000_000_000.0) as u64,
            store,
            endpoint,
            _router: router,
            state_path,
            state,
            tx,
            pending: std::sync::Mutex::new(HashSet::new()),
            bytes: AtomicU64::new(init_bytes),
            items: AtomicU64::new(init_items),
            fetched_ok: AtomicU64::new(0),
            fetched_fail: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
        });
        tokio::spawn(Self::worker(me.clone(), rx));
        tracing::info!(
            "media seeding ON · budget {:.1} GB · restored {} file(s) ({:.1} MB) · media endpoint {}",
            limit_gb,
            init_items,
            init_bytes as f64 / 1e6,
            me.endpoint_id
        );
        Ok(me)
    }

    /// Уже раздаём этот hash?
    pub async fn has(&self, hash: &str) -> bool {
        self.state.lock().await.contains_key(hash)
    }

    /// Снимок раздаваемых медиа (для `GET /media`), свежие первыми, ≤ `cap`.
    pub async fn list(&self, cap: usize) -> Vec<(String, MediaItem)> {
        let g = self.state.lock().await;
        let mut v: Vec<(String, MediaItem)> = g.iter().map(|(k, m)| (k.clone(), m.clone())).collect();
        v.sort_by(|a, b| b.1.ts.cmp(&a.1.ts));
        v.truncate(cap);
        v
    }

    /// Принять анонс: валидация → очередь докачки. Возвращает статус для ответа.
    pub async fn announce(&self, a: AnnounceIn) -> Result<&'static str, String> {
        let hash: Hash = a.h.trim().parse().map_err(|_| "bad hash".to_string())?;
        if a.s > MEDIA_MAX_FILE_BYTES {
            return Err(format!("file too big (max {} MB)", MEDIA_MAX_FILE_BYTES / 1024 / 1024));
        }
        let mut providers: Vec<EndpointId> = Vec::new();
        for s in std::iter::once(a.n.as_str()).chain(a.p.iter().map(|s| s.as_str())).take(9) {
            if let Ok(e) = s.trim().parse::<EndpointId>() {
                if e.to_string() != self.endpoint_id && !providers.contains(&e) {
                    providers.push(e);
                }
            }
        }
        if providers.is_empty() {
            return Err("no valid provider endpoint".to_string());
        }
        let key = hash.to_string();
        if self.state.lock().await.contains_key(&key) {
            return Ok("have");
        }
        {
            let mut p = self.pending.lock().unwrap();
            if p.contains(&key) {
                return Ok("queued");
            }
            if p.len() >= QUEUE_CAP {
                return Err("queue full".to_string());
            }
            p.insert(key.clone());
        }
        match self.tx.try_send(Job { hash, providers, size_hint: a.s }) {
            Ok(()) => Ok("queued"),
            Err(_) => {
                self.pending.lock().unwrap().remove(&key);
                Err("queue full".to_string())
            }
        }
    }

    async fn worker(me: Arc<MediaSeeder>, mut rx: mpsc::Receiver<Job>) {
        let sem = Arc::new(tokio::sync::Semaphore::new(PARALLEL_FETCHES));
        while let Some(job) = rx.recv().await {
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let me2 = me.clone();
            tokio::spawn(async move {
                me2.process(job).await;
                drop(permit);
            });
        }
    }

    async fn process(&self, job: Job) {
        let key = job.hash.to_string();
        let short: String = key.chars().take(12).collect();
        let res = self.fetch(&job).await;
        self.pending.lock().unwrap().remove(&key);
        match res {
            Ok(size) => {
                let provider = job.providers.first().map(|p| p.to_string()).unwrap_or_default();
                {
                    let mut st = self.state.lock().await;
                    st.insert(key.clone(), MediaItem { size, ts: now_secs(), provider });
                    self.persist(&st);
                }
                self.fetched_ok.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    "media seeded {}… ({:.1} MB) — {} file(s), {:.1}/{:.1} MB",
                    short,
                    size as f64 / 1e6,
                    self.items.load(Ordering::Relaxed),
                    self.bytes.load(Ordering::Relaxed) as f64 / 1e6,
                    self.limit as f64 / 1e6
                );
            }
            Err(e) => {
                self.fetched_fail.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("media {}… not fetched ({} provider(s)): {}", short, job.providers.len(), e);
            }
        }
    }

    /// Докачка блоба у провайдеров (с повторами). Возвращает размер блоба.
    async fn fetch(&self, job: &Job) -> Result<u64, String> {
        self.evict_if_needed(job.size_hint.max(1)).await;
        let h = job.hash;
        let mut last_err = String::from("no provider served the blob");
        for attempt in 0..FETCH_ATTEMPTS {
            if let Ok(BlobStatus::Complete { size }) = self.store.blobs().status(h).await {
                return self.accept_size(size).await;
            }
            if let Err(e) = self
                .store
                .downloader(&self.endpoint)
                .download(h, job.providers.clone())
                .await
            {
                last_err = format!("{:?}", e);
            }
            match self.store.blobs().status(h).await {
                Ok(BlobStatus::Complete { size }) => return self.accept_size(size).await,
                Ok(BlobStatus::Partial { size }) => {
                    last_err = format!("partial blob ({} bytes)", size.unwrap_or(0))
                }
                Ok(BlobStatus::NotFound) => {
                    last_err = "provider returned no data (blob absent or refused)".to_string()
                }
                Err(e) => last_err = format!("status check failed: {}", e),
            }
            if attempt + 1 < FETCH_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(3 * (attempt as u64 + 1))).await;
            }
        }
        Err(last_err)
    }

    /// Блоб докачан, но превысил потолок — не раздаём (GC подчистит).
    async fn accept_size(&self, size: u64) -> Result<u64, String> {
        if size > MEDIA_MAX_FILE_BYTES {
            return Err(format!("blob too big ({} MB) — dropped", size / 1024 / 1024));
        }
        Ok(size)
    }

    /// Уборка: если занято + входящий > 90% бюджета, удаляем самые старые медиа,
    /// пока не освободим 50% занятого. Блобы физически чистит GC стора.
    async fn evict_if_needed(&self, incoming: u64) {
        let threshold = (self.limit as f64 * MEDIA_EVICT_FILL_RATIO) as u64;
        let mut st = self.state.lock().await;
        let used: u64 = st.values().map(|m| m.size).sum();
        if used.saturating_add(incoming) <= threshold {
            return;
        }
        let goal = (used as f64 * MEDIA_EVICT_DROP_RATIO) as u64;
        let mut by_age: Vec<(String, u64, u64)> =
            st.iter().map(|(k, m)| (k.clone(), m.ts, m.size)).collect();
        by_age.sort_by(|a, b| a.1.cmp(&b.1));
        let mut freed = 0u64;
        let mut n = 0u64;
        for (k, _, sz) in by_age {
            if freed >= goal {
                break;
            }
            st.remove(&k);
            freed = freed.saturating_add(sz);
            n += 1;
        }
        if n > 0 {
            self.evicted.fetch_add(n, Ordering::Relaxed);
            self.persist(&st);
            tracing::info!(
                "media eviction: disk >{:.0}% — dropped {} oldest file(s), freed {:.1} MB",
                MEDIA_EVICT_FILL_RATIO * 100.0,
                n,
                freed as f64 / 1e6
            );
        }
    }

    fn persist(&self, st: &HashMap<String, MediaItem>) {
        self.bytes.store(st.values().map(|m| m.size).sum(), Ordering::Relaxed);
        self.items.store(st.len() as u64, Ordering::Relaxed);
        if let Ok(json) = serde_json::to_string(st) {
            let _ = std::fs::write(&self.state_path, json);
        }
    }
}
