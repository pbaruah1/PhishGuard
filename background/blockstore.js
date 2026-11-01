                                                                            
                          
  
                                                                                  
                                                                            
                                                                         
                                                          
  
                                                                      
                                                                        
                                                                  
                                                                          
                                          
  
                                                                       
                                                                            
                                                                          
                                                             
  
                                                                         
                                                                           
                                                                        
                                                                        
                                 
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.Blockstore = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

                                                                           
                                                                             
                                                                      
  const DB_NAME = 'parry';
  const STORE_NAME = 'blockset';
  const DB_VERSION = 1;
  const RECORD_KEY = 'feed';

  function hasIndexedDB() { return typeof indexedDB !== 'undefined' && indexedDB; }

  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function idbGet(key) {
    const db = await openDB();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const req = tx.objectStore(STORE_NAME).get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    } finally { db.close(); }
  }

  async function idbPut(key, value) {
    const db = await openDB();
    try {
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        tx.objectStore(STORE_NAME).put(value, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally { db.close(); }
  }

                                                                     
  let cache = null;                                                          
  let readyPromise = null;

  async function rehydrate() {
    if (!hasIndexedDB()) { cache = null; return cache; }
    try {
      const rec = await idbGet(RECORD_KEY);
      cache = rec || null;
    } catch (_) { cache = null;                                                       }
    return cache;
  }

                                                                           
                                                                   
  function ready() {
    if (!readyPromise) readyPromise = rehydrate();
    return readyPromise;
  }

                                                                             
                                                                         
  async function get() {
    await ready();
    return cache;
  }

                                                                           
                                                                     
                                       
  async function save(next) {
    await ready();
    if (hasIndexedDB()) await idbPut(RECORD_KEY, next);
    cache = next;
    readyPromise = Promise.resolve(next);
    return next;
  }

                                                                         
                                                                              
  async function clear() {
    if (hasIndexedDB()) { try { await idbPut(RECORD_KEY, null); } catch (_) {} }
    cache = null;
    readyPromise = Promise.resolve(null);
  }

  return { DB_NAME, STORE_NAME, RECORD_KEY, hasIndexedDB, ready, get, save, clear };
});
