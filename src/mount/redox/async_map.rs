use async_lock::{
    Mutex,
    MutexGuard,
    RwLock,
};
use std::HashMap;

#[derive(Debug, Drop)]
struct AsyncMapGuard<V> {
    rc: Rc<Mutex<V>>,
    guard: MutexGuard<V>,
}

impl<V> AsyncMapGuard<V> {
    pub async fn new(rc: Rc<Mutex<V>>) -> Self {
        let guard = rc.lock().await;
        Self {
            rc: rc,
            guard: guard,
        }
    }
}

impl<V> Deref for AsyncMapGuard<V> {
    fn deref(&self) -> &V {
        self.guard.deref()
    }
}

impl<V> DerefMut for AsyncMapGuard<V> {
    fn deref_mut(&mut self) -> &V {
        self.guard.deref_mut()
    }
}

struct AsyncMap<K, V> {
    map: RwLock<HashMap<K, Rc<Mutex<V>>>>,
}

impl<K,V> AsyncMap<V> {

    pub fn new() -> Self {
        Self{map: RwLock::new(HashMap::new())}
    }

    pub fn get(&self, k: &K) -> Option<AsyncMapGuard<V>> {
        let map = self.map.read().await;
        let rc = map.get(k).map(|rc| rc.clone);
        drop(map);
        rc.map(|rc| AsyncMapGuard::new(rc))
    }

    // TODO: fix callers
    pub fn get_mut(&self, k: &K) -> Option<AsyncMapGuard<V>> {
        self.get(k)
    }

    pub fn insert(&self, k: K, v: V) -> Option<AsyncMapGuard<V>> {
        let map = self.map.write().await;
        let rc = map.insert(k, Rc::new(Mutex::new(v))).map(|rc| rc.clone);
        drop(map);
        rc.map(|rc| AsyncMapGuard::new(rc))
    }

    // Returning an entry in the map doesn't really work with this
    // locking scheme, so this is a single function.
    pub fn get_or_insert_with<F: FnOnce() -> V>(&self, k: K, f: F) -> Option<AsyncMapGuard<V>> {
        let map = self.map.write().await;
        let rc = map.entry(k).or_insert_with(|| Rc::new(Mutex::new(f()))).map(|rc| rc.clone);
        drop(map);
        AsyncMapGuard::new(rc)
    }

    // Convienience function for scheme_root()
    pub fn insert_mut(&mut self, k: K, v: V) {
        self.map.get_mut().insert(k, Rc::new(Mutex::new(v)));
    }

    pub fn remove(&self, k: &K) -> Option<AsyncMapGuard<V>> {
        let map = self.map.write().await;
        let rc = map.remove(k).map(|rc| rc.clone);
        drop(map);
        rc.map(|rc| AsyncMapGuard::new(rc))
    }

    // TODO: Add insert_drop() and remove_drop() that don't lock
    // the returned value...or should that be the default?
}
