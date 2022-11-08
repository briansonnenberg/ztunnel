use std::fmt;
use std::collections::{HashSet, HashMap};
use std::sync::{Arc, RwLock};
use tokio::time::{sleep, Duration};
use tracing::instrument;
use tokio::sync;

use super::CaClient;
use super::Error;
use crate::tls;
use tracing::{info, warn};

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Identity {
    Spiffe {
        trust_domain: String,
        namespace: String,
        service_account: String,
    },
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Identity::Spiffe {
                trust_domain,
                namespace,
                service_account,
            } => write!(
                f,
                "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"
            ),
        }
    }
}

#[derive(Clone)]
pub struct SecretManager {
    client: CaClient,
    outstanding_ca_requests: Arc<sync::RwLock<HashSet<Identity>>>,
    cache: Arc<RwLock<HashMap<Identity, tls::Certs>>>,
}

impl SecretManager {
    pub fn new(cfg: crate::config::Config) -> SecretManager {
        let caclient = CaClient::new(cfg.auth);
        let outstanding_ca_requests: HashSet<Identity> = Default::default();
        let cache: HashMap<Identity, tls::Certs> = Default::default();
        SecretManager {
            client: caclient,
            outstanding_ca_requests: Arc::new(sync::RwLock::new(outstanding_ca_requests)),
            cache: Arc::new(RwLock::new(cache))
        }
    }

    pub async fn refresh_handler(id: Identity, ctx: SecretManager, initial_sleep_time: Duration) {
        info!("refreshing certs for id {} in {:?} seconds", id, initial_sleep_time);
        sleep(initial_sleep_time).await;
        loop {
            match ctx.client.clone().fetch_certificate(id.clone()).await {
                Err(e) => {
                    // Cert refresh has failed. Drop cert from the cache.
                    warn!("Failed cert refresh for id {:?}: {:?}", id, e);
                    {
                        let mut locked_cache = ctx.cache.write().unwrap();
                        locked_cache.remove(&id.clone());
                    }
                    return;
                }
                Ok(fetched_certs) => {
                    info!("refreshed certs {:?}", fetched_certs);
                    {
                        let mut locked_cache = ctx.cache.write().unwrap();
                        locked_cache.insert(id.clone(), fetched_certs.clone());
                    }
                    let sleep_dur = fetched_certs.get_duration_until_refresh();
                    info!("refreshing certs for id {} in {:?} seconds", id, sleep_dur);
                    sleep(sleep_dur).await;
                }
            }
        }
    }

    #[instrument(skip_all, fields(%id))]
    pub async fn fetch_certificate(&mut self, id: &Identity) -> Result<tls::Certs, Error> {
        // Check cache first
        {
            let locked_cache = self.cache.read().unwrap();
            let cache_certs: std::option::Option<&tls::Certs> = locked_cache.get(id);
            if cache_certs.is_some() {
                return Ok(cache_certs.unwrap().clone())
            }
        }

        loop {
            // Bottleneck here waiting for the write lock for the list of outstanding ca requests.
            let mut write_locked_reqs = self.outstanding_ca_requests.write().await;
            if !write_locked_reqs.contains(id) {
                // No other thread has reached this point and indicated they are requesting.  Indicate that we will.
                write_locked_reqs.insert(id.clone());
                break;
            } else {
                // Another thread started the request before we took the write lock.  Wait for it to finish.
                drop(write_locked_reqs);
                loop {
                    let read_locked_reqs = self.outstanding_ca_requests.read().await;
                    if !read_locked_reqs.contains(id) {
                        break;
                    }
                }
                info!("Done waiting, checking cache.");
                // Now check the cache again.  Should have an entry unless the ca request failed
                {
                    let locked_cache = self.cache.read().unwrap();
                    let cache_certs: std::option::Option<&tls::Certs> = locked_cache.get(id);
                    info!("cache certs for req: {:?}", cache_certs);
                    if cache_certs.is_some() {
                        return Ok(cache_certs.unwrap().clone())
                    }
                }
                // other CA request must have failed, try again

        }

        info!("No cache entry, doing fetch...");
        // No cache entry, fetch it and spawn refresh handler
        let fetched_certs_res = self.client.clone().fetch_certificate(id.clone()).await;
        match fetched_certs_res {
            Err(e) => {
                let mut write_locked_reqs = self.outstanding_ca_requests.write().await;
                write_locked_reqs.remove(id);
                return Err(e);
            },
            Ok(fetched_certs) => {
                info!("fetched certs {:?}", fetched_certs);
                {
                    let mut locked_cache = self.cache.write().unwrap();
                    /* locked_cache.insert(id.clone(), fetched_certs.clone()); */
                }
              /*   tokio::spawn(SecretManager::refresh_handler(
                    id.clone(),
                    self.clone(),
                    fetched_certs.get_duration_until_refresh())); */
                {
                    let mut write_locked_reqs = self.outstanding_ca_requests.write().await;
                    warn!("pre: {:?}", write_locked_reqs);
                    write_locked_reqs.remove(id);
                    warn!("post: {:?}", write_locked_reqs);
                }
                Ok(fetched_certs)
            }
        }
    }
}
