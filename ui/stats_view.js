                                                                  
  
                                                                       
                                                                            
                                                                               
                                                                            
                                                     
  
                                                                               
                                  
(function (root, factory) {
  const req = typeof require === 'function';
  const mod = factory(req ? require('../background/stats.js') : root.SSStats);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.SSStatsView = mod;
})(typeof globalThis !== 'undefined' ? globalThis : self, function (SSStats) {
  'use strict';

  const DAY = 86400000;
                                                                                
                                                                             
                                                
  const ALL_MAX_DAYS = 90;
                                                                              
                                                                    
  const MAX_BARS = 14;
  const FIELDS = ['checked', 'threats', 'privacy'];

  function num(v) {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }
  function at(now) {
    return typeof now === 'number' && Number.isFinite(now) ? now : Date.now();
  }
                                                                             
                                    
  function dayKey(t) { return new Date(t).toISOString().slice(0, 10); }
  function startOfDay(t) { return Date.parse(dayKey(t) + 'T00:00:00Z'); }

                                                                             
                                                                               
                                                   
  function spanDays(period, now, installedAt) {
    const p = String(period);
    if (p === '7' || p === '30') return { days: Number(p), clamped: false };
    const t = at(now);
    const inst = (typeof installedAt === 'number' && Number.isFinite(installedAt) && installedAt > 0) ? installedAt : t;
    const raw = Math.round((startOfDay(t) - startOfDay(inst)) / DAY) + 1;
    const days = Math.min(Math.max(raw, 1), ALL_MAX_DAYS);
    return { days, clamped: raw > ALL_MAX_DAYS };
  }

                                                                             
                                                                         
                                                                            
                                                                               
                                                                               
                                   
  function series(statsDaily, period, now, installedAt) {
    const { days, clamped } = spanDays(period, now, installedAt);
    const grouped = String(period) !== '7' && String(period) !== '30';
    const byDay = new Map();
    for (const b of (Array.isArray(statsDaily) ? statsDaily : [])) {
      if (!b || typeof b.d !== 'string') continue;
      byDay.set(b.d, b);
    }
    const end = startOfDay(at(now));
    const start = end - (days - 1) * DAY;
    const groupDays = (grouped && days > MAX_BARS) ? Math.ceil(days / MAX_BARS) : 1;

    const bars = [];
    for (let toT = end; toT >= start; toT -= groupDays * DAY) {
      const fromT = Math.max(toT - (groupDays - 1) * DAY, start);
      const bar = { from: dayKey(fromT), to: dayKey(toT), days: Math.round((toT - fromT) / DAY) + 1, checked: 0, threats: 0, privacy: 0 };
      for (let t = fromT; t <= toT; t += DAY) {
        const rec = byDay.get(dayKey(t));
        if (!rec) continue;
        for (const f of FIELDS) bar[f] += num(rec[f]);
      }
      bars.unshift(bar);
    }
    return { period: String(period), days, groupDays, clamped, from: dayKey(start), to: dayKey(end), bars };
  }

                                                                              
                                                                                
                                                     
  function heights(bars) {
    const max = (Array.isArray(bars) ? bars : []).reduce((m, b) => Math.max(m, num(b && b.checked)), 0);
    return (Array.isArray(bars) ? bars : []).map((b) => (max > 0 ? Math.round(num(b && b.checked) / max * 100) : 0));
  }

                                                                               
                                                                          
                                                                          
                                                                    
  function catRows(threatsByType, categories) {
    const cats = Array.isArray(categories) && categories.length
      ? categories
      : ((SSStats && SSStats.CATEGORIES) || []);
    const src = (threatsByType && typeof threatsByType === 'object') ? threatsByType : {};
    const rows = cats.map((key, i) => ({ key, count: num(src[key]), order: i }));
    const max = rows.reduce((m, r) => Math.max(m, r.count), 0);
    rows.sort((a, b) => (b.count - a.count) || (a.order - b.order));
    return rows.map((r) => ({ key: r.key, count: r.count, pct: max > 0 ? Math.round(r.count / max * 100) : 0 }));
  }

  return { DAY, ALL_MAX_DAYS, MAX_BARS, dayKey, spanDays, series, heights, catRows };
});
