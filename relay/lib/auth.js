'use strict';
                                                                             
const crypto = require('node:crypto');
function tokenOk(auth, secret) {
  if (!secret) return false;
  const a = Buffer.from(String(auth));
  const b = Buffer.from('Bearer ' + secret);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
module.exports = { tokenOk };
