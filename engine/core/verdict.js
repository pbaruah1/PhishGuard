(function (root, factory) {
  const mod = factory(typeof require === 'function' ? require('./constants') : root.PhishGuard, root);
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function (C, root) {
  'use strict';
  const { THRESHOLDS } = C;

  function fuse({ modelProb, urlRules, domRules, contentProb, iconMatch }) {
    const u = urlRules || { score: 0, reasons: [] };
    const d = domRules || { score: 0, reasons: [], flags: [] };
    const uScore = u.score || 0;
    const dScore = d.score || 0;
    const dIndependentScore = Number.isFinite(Number(d.independentScore)) ? Number(d.independentScore) : dScore;
    const ruleScore = Math.max(uScore, dScore);
    const corroborationRuleScore = Math.max(uScore, dIndependentScore);

                                                                   
                                                                               
                                                                        
                                                                          
                                                                        
                                                                      
                                                                             
                                                                            
                                                                         
                                                                          
                                                                        
                                                                        
                                                                           
                                                     
    const uRisk = Math.min(u.riskScore || 0, uScore);
    const riskInRuleScore = uScore >= dScore ? uRisk : 0;
    const ruleScoreExRisk = Math.max(0, ruleScore - riskInRuleScore);

                                                                                 
                                                                                 
                                                                                 
                                                                        
    const modelUsed = typeof modelProb === 'number' && !Number.isNaN(modelProb);
    let score = !modelUsed ? ruleScore : Math.max(ruleScore, (ruleScore + modelProb) / 2);
    let scoreExRisk = !modelUsed ? ruleScoreExRisk : Math.max(ruleScoreExRisk, (ruleScoreExRisk + modelProb) / 2);

                                                                               
                                                                         
                                                                      
    if ((d.flags || []).includes('credential-form-foreign-domain')) {
      score = Math.max(score, 0.9);
      scoreExRisk = Math.max(scoreExRisk, 0.9);
    }

                                                                         
                                                                            
    const contentUsed = typeof contentProb === 'number' && !Number.isNaN(contentProb);
    const contentReasons = [];
    if (contentUsed) {
      const pm = (typeof root !== 'undefined' && root.PhishGuard && root.PhishGuard.PAGE_MODEL) || null;
      const t = (pm && pm.thresholds && pm.thresholds.suspicious) || THRESHOLDS.contentSuspicious;
      if (contentProb >= t) {
                                                                             
                                                                                  
                                                                             
                                                                             
                                                                              
                                                                          
                                                                              
                                                                            
                                                                       
                                                                             
                                                     
        const urlModelCorroborates = modelUsed && modelProb >= THRESHOLDS.contentCorroborateModel &&
          uScore >= THRESHOLDS.contentCorroborateModelMinRule;
        const corroborated = corroborationRuleScore >= THRESHOLDS.contentCorroborateRule ||
          urlModelCorroborates || iconMatch === true;
        score = Math.max(score, corroborated ? THRESHOLDS.dangerous : THRESHOLDS.suspicious);

                                                                        
                                                                          
                                                                           
                                                                           
        const uScoreExRisk = uScore - uRisk;
        const urlModelCorroboratesExRisk = modelUsed && modelProb >= THRESHOLDS.contentCorroborateModel &&
          uScoreExRisk >= THRESHOLDS.contentCorroborateModelMinRule;
        const independentRuleScoreExRisk = Math.max(uScore - uRisk, dIndependentScore);
        const corroboratedExRisk = independentRuleScoreExRisk >= THRESHOLDS.contentCorroborateRule ||
          urlModelCorroboratesExRisk || iconMatch === true;
        scoreExRisk = Math.max(scoreExRisk, corroboratedExRisk ? THRESHOLDS.dangerous : THRESHOLDS.suspicious);

        contentReasons.push({ code: 'contentPhishingPattern', kind: 'page' });
      }
    }
    score = Math.max(0, Math.min(1, score));
    scoreExRisk = Math.max(0, Math.min(1, scoreExRisk));

                                                                             
                                                                            
                                                                          
                                              
    let level = 'safe';
    if (scoreExRisk >= THRESHOLDS.dangerous) level = 'dangerous';
    else if (score >= THRESHOLDS.suspicious) level = 'suspicious';

                                                                              
                                                                 
    const reasons = [];
    const seen = new Set();
    for (const r of [...(u.reasons || []), ...(d.reasons || []), ...contentReasons]) {
      const key = (r && typeof r === 'object') ? (r.code + '|' + JSON.stringify(r.params || [])) : String(r);
      if (seen.has(key)) continue;
      seen.add(key);
      reasons.push(r);
    }
    const reasonCodes = reasons.filter((r) => r && r.code).map((r) => r.code);
    return {
      level, score: Number(score.toFixed(4)), reasons, reasonCodes, modelUsed, contentUsed,
      brand: d.brand, flags: d.flags || [],
                                                                              
                                                                            
                                                                              
                                                                            
      riskScore: Number(riskInRuleScore.toFixed(4))
    };
  }

                                                                           
                                                                          
                                                                          
                                                                           
                                                                       
                                                                        
                                                                          
                                                                           
                                                                          
                                                                       
                                                                        
                                                                          
                                                                        
    
                                                                          
                                                                        
                                                                            
                                                                           
                                                                             
                                                                             
                                                                       
                                                                           
                                                                      
                                                                 
                                                                          
                                                                         
                                                                          
                                                                             
                                                                           
               
  function foldRiskEvidence(verdict, delta, reason, flag, opts) {
    const v = verdict || { level: 'safe', score: 0, riskScore: 0, reasons: [], reasonCodes: [], flags: [] };
    if (v.level === 'dangerous') return v;                                              
    const riskScore = (v.riskScore || 0) + delta;
    const score = Math.min(1, (v.score || 0) + delta);
    let level = v.level;
    if ((score - riskScore) >= THRESHOLDS.dangerous) level = 'dangerous';
    else if (score >= THRESHOLDS.suspicious) level = 'suspicious';
    else if (opts && opts.minLevel === 'suspicious' && level === 'safe') level = 'suspicious';
    return Object.assign({}, v, {
      level, score, riskScore: Number(riskScore.toFixed(4)),
      reasons: [reason].concat(v.reasons || []),
      reasonCodes: [reason.code].concat(v.reasonCodes || []),
      flags: [flag].concat(v.flags || [])
    });
  }

                                                                          
                                                                            
                                                                      
                                                                        
                                                                 
  function promoteFeedWarn(verdict, signals, urlRules, domRules) {
    const v = verdict || {}; const flags = v.flags || [];
    if (!flags.includes('feed-warn') || v.level === 'dangerous') return verdict;
    const pw = !!(signals && signals.hasPasswordField);
    const brandEvidence = (urlRules && (urlRules.reasons || []).some((r) => ['brandFuzzyMatch', 'brandLookalike', 'brandForeignSuffix', 'idnHomograph'].includes(r.code)))
      || (domRules && (domRules.flags || []).some((f) => f.startsWith('brand-impersonation')));
    const nrd = flags.includes('new-domain');
    if (!(pw && (brandEvidence || nrd))) return verdict;
    return Object.assign({}, v, { level: 'dangerous', score: Math.max(v.score || 0, 0.9), flags: ['feed-warn-corroborated'].concat(flags) });
  }

  return { fuse, foldRiskEvidence, promoteFeedWarn };
});
