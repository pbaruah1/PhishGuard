'use strict';
                                                                
const buckets = new Map();
function allow(ip, limit = 60, windowMs = 3600000) {
  const now = Date.now(); const b = buckets.get(ip) || { n: 0, reset: now + windowMs };
  if (now > b.reset) { b.n = 0; b.reset = now + windowMs; }
  b.n++; buckets.set(ip, b);
  if (buckets.size > 10000) buckets.delete(buckets.keys().next().value);
  return b.n <= limit;
}
                                                                                 
                                                                                    
                                                                                   
                                                                              
                                    
function clientIp(headers) {
  headers = headers || {};
  let ip = headers['x-real-ip'];
  if (!ip) {
    const xff = String(headers['x-forwarded-for'] || '');
    if (xff) {
      const parts = xff.split(',');
      ip = parts[parts.length - 1];
    }
  }
  ip = String(ip || '').trim();
  if (!ip) ip = 'unknown';
  if (ip.length > 64) ip = ip.slice(0, 64);
  return ip;
}
module.exports = { allow, clientIp, _reset: () => buckets.clear() };
