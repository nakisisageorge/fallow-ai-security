//! Verification cache for AI security findings.

use super::AiVerificationResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Cache directory not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCacheEntry {
    pub result: AiVerificationResult,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub access_count: u64,
}

/// File-based cache for AI verification results.
pub struct VerificationCache {
    cache_dir: PathBuf,
    memory_cache: Mutex<HashMap<String, VerificationCacheEntry>>,
    max_entries: usize,
}

impl VerificationCache {
    /// Create a new verification cache.
    pub fn new(cache_dir: impl Into<PathBuf>, max_entries: usize) -> Result<Self, CacheError> {
        let cache_dir = cache_dir.into();
        fs::create_dir_all(&cache_dir)?;
        
        Ok(Self {
            cache_dir,
            memory_cache: Mutex::new(HashMap::new()),
            max_entries,
        })
    }
    
    /// Get a cached verification result.
    pub fn get(&self, key: &str) -> Option<AiVerificationResult> {
        // Check memory cache first
        if let Ok(mut cache) = self.memory_cache.lock() {
            if let Some(entry) = cache.get_mut(key) {
                entry.access_count += 1;
                return Some(entry.result.clone());
            }
        }
        
        // Check disk cache
        let path = self.cache_dir.join(format!("{}.json", key));
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(entry) = serde_json::from_str::<VerificationCacheEntry>(&content) {
                    let mut entry = entry;
                    entry.access_count += 1;
                    let result = entry.result.clone();
                    
                    // Update memory cache
                    if let Ok(mut cache) = self.memory_cache.lock() {
                        if cache.len() >= self.max_entries {
                            // Simple eviction: remove oldest
                            if let Some(oldest_key) = cache.keys().next().cloned() {
                                cache.remove(&oldest_key);
                            }
                        }
                        cache.insert(key.to_string(), entry);
                    }
                    
                    // Update disk cache
                    let _ = self.set(key, &result);
                    
                    return Some(result);
                }
            }
        }
        
        None
    }
    
    /// Set a verification result in the cache.
    pub fn set(&self, key: &str, result: &AiVerificationResult) -> Result<(), CacheError> {
        let entry = VerificationCacheEntry {
            result: result.clone(),
            created_at: chrono::Utc::now(),
            access_count: 1,
        };
        
        // Update memory cache
        if let Ok(mut cache) = self.memory_cache.lock() {
            if cache.len() >= self.max_entries && !cache.contains_key(key) {
                if let Some(oldest_key) = cache.keys().next().cloned() {
                    cache.remove(&oldest_key);
                }
            }
            cache.insert(key.to_string(), entry.clone());
        }
        
        // Update disk cache
        let path = self.cache_dir.join(format!("{}.json", key));
        let content = serde_json::to_string_pretty(&entry)?;
        fs::write(path, content)?;
        
        Ok(())
    }
    
    /// Clear the cache.
    pub fn clear(&self) -> Result<(), CacheError> {
        if let Ok(mut cache) = self.memory_cache.lock() {
            cache.clear();
        }
        
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if entry.path().extension().is_some_and(|ext| ext == "json") {
                fs::remove_file(entry.path())?;
            }
        }
        
        Ok(())
    }
    
    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        let memory_count = self.memory_cache.lock().map(|c| c.len()).unwrap_or(0);
        let disk_count = fs::read_dir(&self.cache_dir)
            .map(|dir| {
                dir.filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
                    .count()
            })
            .unwrap_or(0);
        
        CacheStats {
            memory_entries: memory_count,
            disk_entries: disk_count,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub memory_entries: usize,
    pub disk_entries: usize,
}

/// Global cache instance.
static GLOBAL_CACHE: OnceLock<VerificationCache> = OnceLock::new();

/// Initialize the global cache.
pub fn init_global_cache(
    cache_dir: impl Into<PathBuf>,
    max_entries: usize,
) -> Result<(), CacheError> {
    let cache = VerificationCache::new(cache_dir, max_entries)?;
    GLOBAL_CACHE.set(cache).map_err(|_| {
        CacheError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Global cache already initialized",
        ))
    })
}

/// Get the global cache instance.
pub fn global_cache() -> Option<&'static VerificationCache> {
    GLOBAL_CACHE.get()
}