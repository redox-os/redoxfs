use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use async_lock::{Mutex, MutexGuardArc, RwLock};

pub struct AsyncMap<K: Ord + PartialOrd, V> {
    map: RwLock<BTreeMap<K, Arc<Mutex<V>>>>,
}

impl<K: Ord + PartialOrd, V> AsyncMap<K, V> {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(BTreeMap::new()),
        }
    }

    // Note that in all cases below we drop() the map before awaiting
    // the Mutex.

    pub async fn get(&self, k: &K) -> Option<MutexGuardArc<V>> {
        let map = self.map.read().await;
        let lock = map.get(k).map(|v| v.lock_arc());
        drop(map);
        match lock {
            Some(fut) => Some(fut.await),
            None => None,
        }
    }

    // TODO: fix callers
    pub async fn get_mut(&self, k: &K) -> Option<MutexGuardArc<V>> {
        self.get(k).await
    }

    pub async fn insert(&self, k: K, v: V) -> Option<MutexGuardArc<V>> {
        let mut map = self.map.write().await;
        let lock = map.insert(k, Arc::new(Mutex::new(v))).map(|v| v.lock_arc());
        drop(map);
        match lock {
            Some(fut) => Some(fut.await),
            None => None,
        }
    }

    // Returning an entry in the map doesn't really work with this
    // locking scheme, so this is a single function.
    pub async fn get_or_insert_with<F: FnOnce() -> V>(&self, k: K, f: F) -> MutexGuardArc<V> {
        let mut map = self.map.write().await;
        let lock = map
            .entry(k)
            .or_insert_with(|| Arc::new(Mutex::new(f())))
            .lock_arc();
        drop(map);
        lock.await
    }

    // Convienience function for scheme_root()
    pub fn insert_mut(&mut self, k: K, v: V) {
        self.map.get_mut().insert(k, Arc::new(Mutex::new(v)));
    }

    pub async fn remove(&self, k: &K) -> Option<MutexGuardArc<V>> {
        let mut map = self.map.write().await;
        let lock = map.remove(k).map(|v| v.lock_arc());
        drop(map);
        match lock {
            Some(fut) => Some(fut.await),
            None => None,
        }
    }

    // TODO: Add insert_drop() and remove_drop() that don't lock
    // the returned value...or should that be the default?
}
