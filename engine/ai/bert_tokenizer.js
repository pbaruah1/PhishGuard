(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod;
  root.PhishGuard = Object.assign(root.PhishGuard || {}, mod);
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  const CLS = '[CLS]';
  const SEP = '[SEP]';
  const UNK = '[UNK]';
  const PAD = '[PAD]';

  function isWhitespace(code) {
    return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d || code === 0x00a0 ||
      (code >= 0x2000 && code <= 0x200a) || code === 0x202f || code === 0x205f || code === 0x3000;
  }
  function isControl(code) {
    return (code >= 0 && code <= 0x1f && !isWhitespace(code)) || (code >= 0x7f && code <= 0x9f);
  }
  function isPunctuation(char) {
    return /[!-/:-@\[-`\{-~]/.test(char) || /\p{P}/u.test(char);
  }
  function isCjk(code) {
    return (code >= 0x4e00 && code <= 0x9fff) || (code >= 0x3400 && code <= 0x4dbf) ||
      (code >= 0x20000 && code <= 0x2a6df) || (code >= 0x2a700 && code <= 0x2b73f) ||
      (code >= 0x2b740 && code <= 0x2b81f) || (code >= 0xf900 && code <= 0xfaff);
  }

  function basicTokenize(text) {
    const source = String(text || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
    const chunks = [];
    let current = '';
    const flush = () => { if (current) { chunks.push(current); current = ''; } };
    for (const char of source) {
      const code = char.codePointAt(0);
      if (isControl(code) || isWhitespace(code)) { flush(); continue; }
      if (isCjk(code)) { flush(); chunks.push(char); continue; }
      if (isPunctuation(char)) { flush(); chunks.push(char); continue; }
      current += char;
    }
    flush();
    return chunks;
  }

  function createBertTokenizer(vocabText) {
    if (typeof vocabText !== 'string' || vocabText.length < 10) throw new TypeError('BERT vocabulary text is missing or too small.');
    const vocab = new Map();
    const lines = vocabText.replace(/^\uFEFF/, '').split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) if (lines[i] && !vocab.has(lines[i])) vocab.set(lines[i], i);
    for (const token of [PAD, UNK, CLS, SEP]) if (!vocab.has(token)) throw new Error('BERT vocabulary is missing ' + token + '.');
    const ids = Object.freeze({ pad: vocab.get(PAD), unk: vocab.get(UNK), cls: vocab.get(CLS), sep: vocab.get(SEP) });

    function wordpiece(token, maxChars = 100) {
      if (token.length > maxChars) return [UNK];
      const pieces = [];
      let start = 0;
      while (start < token.length) {
        let end = token.length;
        let found = null;
        while (start < end) {
          const piece = (start ? '##' : '') + token.slice(start, end);
          if (vocab.has(piece)) { found = piece; break; }
          end--;
        }
        if (!found) return [UNK];
        pieces.push(found);
        start = end;
      }
      return pieces;
    }

    function tokenize(text) {
      const output = [];
      for (const token of basicTokenize(text)) output.push(...wordpiece(token));
      return output;
    }

    function encode(text, options) {
      const opts = options || {};
      const maxLength = Math.max(8, Math.min(512, Math.floor(Number(opts.maxLength) || 128)));
      const pieces = tokenize(text).slice(0, maxLength - 2);
      const tokenIds = [ids.cls];
      for (const piece of pieces) tokenIds.push(vocab.has(piece) ? vocab.get(piece) : ids.unk);
      tokenIds.push(ids.sep);
      const attentionMask = new Array(tokenIds.length).fill(1);
      while (tokenIds.length < maxLength) { tokenIds.push(ids.pad); attentionMask.push(0); }
      return {
        inputIds: tokenIds,
        attentionMask,
        tokenTypeIds: new Array(maxLength).fill(0),
        tokens: [CLS, ...pieces, SEP],
        length: attentionMask.reduce((sum, value) => sum + value, 0)
      };
    }

    return Object.freeze({ tokenize, encode, vocabSize: vocab.size, specialTokenIds: ids });
  }

  return { basicBertTokenize: basicTokenize, createBertTokenizer };
});
