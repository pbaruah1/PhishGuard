                                                                               
  
                                             
  
                                                                    
                                                                        
                                                                    
                                                                             
                                                                       
                                                                   
                                                                             
                                                                            
                                 
  
                                                                          
                                                                            
                                                                         
                                                                           
                                                                             
                                                                          
                                                                    
  
                                                                          
                                                                      
                                                                       
                
  
                                                                             
                                                                         
                                                                         
                                                                    
                                                                       
                                                                 
(function (root, factory) {
  const req = typeof require === 'function';
  const mod = factory(req ? require('../core/constants') : root.PhishGuard);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function (C) {
  'use strict';

  const { BRAND_DOMAINS, BRANDS_BY_KEY, registrableParts, isVerifiedNamespace } = C;
  const MIN_BRAND_LEN = 5;
                                                                           
                                                                      
                                                                           
                                                                       
                                                                            
                                                                             
                                                                            
                                                           
  const TENANT_TOKEN_EXCLUDE = new Set([
                                       
    'apple', 'amazon', 'outlook', 'steam', 'wise', 'grab', 'noon', 'emirates',
    'ups', 'ing', 'fab', 'dib', 'du', 'icp', 'dbs', 'line', 'wish', 'mobile', 'trust',
                                                                          
    'affirm', 'chase', 'chime', 'concur', 'digi', 'discover', 'exodus', 'gemini',
    'greenhouse', 'indeed', 'indigo', 'kraken', 'ledger', 'lever', 'nab', 'notion',
    'orange', 'popular', 'regions', 'scoot', 'slack', 'smart', 'southwest',
    'square', 'stripe', 'target', 'three', 'twitch', 'united', 'zoom'
  ]);
                                                                           
                                                                            
                                                                          
                                                                      
                                                                         
                                                                         
                                                                           
                                                           
  const INJECTION_TOKEN_EXCLUDE = new Set(['ledger']);

                                                                                

  function buildTrie() {
    const trieRoot = {};
    for (const brand of Object.keys(BRAND_DOMAINS)) {
      for (const domain of BRAND_DOMAINS[brand]) {
        const labels = String(domain).toLowerCase().split('.').filter(Boolean).reverse();
        let node = trieRoot;
        for (const label of labels) {
          node.children = node.children || {};
          node = node.children[label] = node.children[label] || {};
        }
        node.brand = brand;                          
      }
    }
    return trieRoot;
  }
  let TRIE = null;
  function trie() { return TRIE || (TRIE = buildTrie()); }
                                                                            
                                                                  
  function _resetTrieForTest() { TRIE = null; }

                                                                     
                                                                             
                                                                            
                                                                             
                                                                            
                                                    
  function allowlistBrandMatch(host) {
    const h = String(host || '').toLowerCase().replace(/\.+$/, '');
    const labels = h.split('.').filter(Boolean).reverse();
    let node = trie();
    let hit = null;
    for (const label of labels) {
      const children = node.children;
      if (!children || !children[label]) break;
      node = children[label];
      if (node.brand) hit = node.brand;                                     
    }
                                                                      
                                                                          
                                                                           
                                                                            
                                                                         
                                                                           
                                                              
    if (!hit && isVerifiedNamespace && isVerifiedNamespace(h)) {
      const hostLabels = h.split('.').filter(Boolean);
      const brandKeys = Object.keys(BRAND_DOMAINS);
      const labelHit = hostLabels.find((lab) => brandKeys.includes(lab));
      return labelHit || '__verified__';
    }
    return hit;
  }

                                                                                 

                                                                           
                                                                           
                                                                            
                                                       
  function fuzzyForm(host) {
    const h = String(host || '').toLowerCase().replace(/\.+$/, '');
    const parts = registrableParts(h);
    if (!parts.suffix) return h;                                         
    const labels = h.split('.').filter(Boolean);
    const suffixLabelCount = parts.suffix.split('.').length;
    return labels.slice(0, Math.max(0, labels.length - suffixLabelCount)).join('.');
  }

                                                                          
                                                                             
                                                                                        
                                                                         
                                                 
  function damerauLevenshtein(a, b) {
    const al = a.length, bl = b.length;
    if (Math.abs(al - bl) > 2) return 3;
    const d = [];
    for (let i = 0; i <= al; i++) d[i] = [i];
    for (let j = 0; j <= bl; j++) d[0][j] = j;
    for (let i = 1; i <= al; i++) {
      for (let j = 1; j <= bl; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
      }
    }
    return d[al][bl];
  }

                                                                      
                                                                 
                                                                                       
                                                                              
                                                                             
                                                                        
                                                            
  function homoglyphVariants(s) {
    const base = String(s).toLowerCase().replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o');
                                                   
    return [base.replace(/1/g, 'l'), base.replace(/1/g, 'i')];
  }
  function tokenMatchesBrand(token, brand) {
    if (token === brand) return true;
    for (const variant of homoglyphVariants(token)) if (variant === brand) return true;
    return false;
  }

                                                                           
                                                                             
                                                                
    
                                                                            
                                                                       
                                                                         
                                                                       
                                                                        
                                                                        
                                                                  
                                                                     
                                                                       
  function buildCandidates() {
    const out = [];
    for (const brand of Object.keys(BRAND_DOMAINS)) {
      const b = BRANDS_BY_KEY && BRANDS_BY_KEY[brand];
      if (b && b.fuzzy === false) continue;
      const domains = BRAND_DOMAINS[brand];
      if (!domains || !domains.length) continue;
      const form = fuzzyForm(domains[0]);
      if (form.length < MIN_BRAND_LEN) continue;
      out.push({ brand, form });
    }
    return out;
  }
  let CANDIDATES = null;
  function candidates() { return CANDIDATES || (CANDIDATES = buildCandidates()); }
  function _resetCandidatesForTest() { CANDIDATES = null; }

  const GRADE_RANK = { strongest: 3, strong: 2, weak: 1 };

                                                                       
                                                                     
                                                                            
                                                                           
                                                                                 
                                                                           
  function gradeAgainst(brand, form, hostForm, subLabels, sld) {
                                                                             
                                                                          
                                                                             
                                                                           
                                                               
                                                                 
    const injectable = brand.length >= 4 && !INJECTION_TOKEN_EXCLUDE.has(brand);
                                                                       
                                                         
    if (injectable) for (const lab of subLabels) {
      if (tokenMatchesBrand(lab, brand)) return { grade: 'strongest', rule: 'a' };
    }
                                                                           
                                                          
                                                                         
                                                         
    const hyphenCandidates = subLabels.concat(sld ? [sld] : []);
    if (injectable) for (const lab of hyphenCandidates) {
      const tokens = lab.split('-');
      if (tokens.length > 1 && tokens.some((t) => tokenMatchesBrand(t, brand))) return { grade: 'strongest', rule: 'b' };
    }
                                                                         
                                                                             
                                                                             
                                                                             
                                                                            
                                                                         
    if (!sld || sld.length < MIN_BRAND_LEN) return null;
                                                                         
                                                                             
                                                          
    if (sld === form) return { grade: 'strong', rule: 'c' };
                                                                  
    for (const variant of homoglyphVariants(sld)) {
      if (variant === form) return { grade: 'strong', rule: 'd' };
    }
                                
    const dist = damerauLevenshtein(sld, form);
    if (dist === 1) return { grade: 'strong', rule: 'e' };
    if (dist === 2 && form.length >= 8) return { grade: 'weak', rule: 'e' };                         
    return null;
  }

                                                                       
                                                                              
                                                                       
                                                  
  function fuzzyBrandMatch(host) {
    const h = String(host || '').toLowerCase();
    const hostForm = fuzzyForm(h);
                                                                  
                                                                            
                                                                
    if (!hostForm) return null;
    const parts = registrableParts(h);
    const labels = h.replace(/\.+$/, '').split('.').filter(Boolean);
    const domainLabelCount = parts.domain ? parts.domain.split('.').length : labels.length;
    const subLabels = labels.slice(0, Math.max(0, labels.length - domainLabelCount));
    let best = null;
    for (const { brand, form } of candidates()) {
      const g = gradeAgainst(brand, form, hostForm, subLabels, parts.sld);
      if (!g) continue;
      if (!best || GRADE_RANK[g.grade] > GRADE_RANK[best.grade]) best = { brand, grade: g.grade, rule: g.rule };
    }
    return best;
  }

                                                                                 
                                                                        
                                                                            
                                                                    
                                                    
  function brandForeignSuffix(host) {
    const h = String(host || '').toLowerCase().replace(/\.+$/, '');
    if (allowlistBrandMatch(h)) return null;
    const parts = registrableParts(h);
    const b = C.BRANDS_BY_KEY && C.BRANDS_BY_KEY[parts.sld];
    if (!b || b.ccPolicy !== 'closed' || !Array.isArray(b.suffixes)) return null;
    return b.suffixes.includes(parts.suffix) ? null : { brand: b.key, suffix: parts.suffix };
  }

                                                                                 
                                                                            
                                     
    
                                         
                                                                             
                                                                           
                                                                              
                                                                          
                                                                            
                                                                           
                                                                    
                                                                           
    
                                                                          
                                                                              
                                                                       
                                                                        
                                                         
  function tenantBrandToken(label) {
    const tokens = String(label || '').toLowerCase().split(/[-_.]+/).filter((t) => t.length >= 3);
    if (!tokens.length) return null;
    const keys = Object.keys(BRAND_DOMAINS).filter((k) => {
      if (TENANT_TOKEN_EXCLUDE.has(k)) return false;
      const b = BRANDS_BY_KEY && BRANDS_BY_KEY[k];
      return !(b && (b.fuzzy === false || b.nameMatch === false));
    });
    for (const t of tokens) for (const k of keys) if (t === k || homoglyphVariants(t).includes(k)) return k;
    return null;
  }

  return {
    MIN_BRAND_LEN, GRADE_RANK, TENANT_TOKEN_EXCLUDE, INJECTION_TOKEN_EXCLUDE,
    allowlistBrandMatch, fuzzyForm, damerauLevenshtein, homoglyphVariants, fuzzyBrandMatch,
    brandForeignSuffix, tenantBrandToken,
    _resetTrieForTest, _resetCandidatesForTest
  };
});
