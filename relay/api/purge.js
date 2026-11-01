'use strict';
                                                
const db = require('../lib/db');
const { tokenOk } = require('../lib/auth');
module.exports = async function handler(req, res) {
  const auth = String(req.headers.authorization || '');
  if (!tokenOk(auth, process.env.CRON_SECRET)) { res.status(401).end(); return; }
                                                                                    
                                                                                 
                                                                                   
                                          
  if (req.headers['x-vercel-cron'] === undefined) { res.status(401).end(); return; }
  try {
    const sql = db.getSql();
    const r = await sql`delete from reports where received_at < now() - interval '180 days'`;
    res.status(200).json({ ok: true, deleted: Array.isArray(r) ? r.length : null });
  } catch (e) { res.status(500).json({ error: 'db' }); }
};
module.exports._setSql = db._setSql;
