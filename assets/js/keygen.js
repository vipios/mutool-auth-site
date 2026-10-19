/*
 * keygen.js — 授权码算法封装
 * 1:1 复刻 MUtool (roothide) 2.2.18 授权机制（见《授权机制可提取内容.md》）：
 *
 *   data   = "<BundleID>|<UDID>"                    如 com.muzi.mutool|00008020-...
 *   mac    = HMAC-SHA256(KEY, data)                 KEY = MuziSource-Auth-2026-v1-Secret-Key
 *   hex    = 大写十六进制（64 字符）
 *   截取   = hex 前 16 字符（长度可自定义，默认 16 = 原版）
 *   分组   = 按 4 字分组，"-" 连接                  → AAAA-BBBB-CCCC-DDDD
 *   最终   = "MUZI-" + 产品代号 + "-" + 分组        → MUZI-MUTOOL-AAAA-BBBB-CCCC-DDDD
 *
 * 对拍向量：UDID 00008020-001A2C3E1E44801E → MUZI-MUTOOL-F33A-5853-E382-290E
 *
 * 平台扩展 — 长度自定义：
 *   数据段长度可调（4–64，默认 16），设置持久化于 localStorage(mutool_keylen)；
 *   验证时按授权码自身的数据段长度自适应计算期望值，
 *   因此任意长度生成的码均可被正确验证，不依赖当前长度设置。
 *   注意：原版客户端固定只认 16 位（4 组），自定义长度码仅在本平台内自洽。
 */
(function (global) {
  'use strict';

  var KEY = 'MuziSource-Auth-2026-v1-Secret-Key';
  var DEFAULTS = {
    bundle: 'com.muzi.mutool',
    product: 'MUTOOL',
    prefix: 'MUZI',
    len: 16 /* 原版固定 16 字符（4 组） */
  };
  var LS_LEN = 'mutool_keylen';
  var MIN_LEN = 4, MAX_LEN = 64;

  function clampLen(n) {
    n = parseInt(n, 10);
    if (!isFinite(n)) n = DEFAULTS.len;
    return Math.min(Math.max(n, MIN_LEN), MAX_LEN);
  }

  /* 当前长度设置（localStorage 持久化，缺省 16） */
  function getLen() {
    try {
      var v = localStorage.getItem(LS_LEN);
      if (v) return clampLen(v);
    } catch (e) { /* 隐私模式等场景下退回默认 */ }
    return DEFAULTS.len;
  }

  function setLen(n) {
    n = clampLen(n);
    try { localStorage.setItem(LS_LEN, String(n)); } catch (e) {}
    return n;
  }

  /* 按 4 字分组（长度非 4 倍数时末组会短一些） */
  function groupHex(body) {
    var parts = [];
    for (var i = 0; i < body.length; i += 4) parts.push(body.substring(i, i + 4));
    return parts.join('-');
  }

  function compute(udid, opts) {
    opts = opts || {};
    var bundle = (opts.bundle || DEFAULTS.bundle).trim();
    var product = (opts.product || DEFAULTS.product).trim().toUpperCase();
    var prefix = (opts.prefix || DEFAULTS.prefix).trim().toUpperCase();
    udid = (udid || '').trim();

    var len = clampLen(opts.len != null && opts.len !== '' ? opts.len : getLen());

    var data = bundle + '|' + udid;
    var hex64 = HMAC.hmacSha256Hex(KEY, data).toUpperCase();
    var body = hex64.substring(0, len);
    var grouped = groupHex(body);
    var code = prefix + '-' + product + '-' + grouped;

    return {
      udid: udid,
      bundle: bundle,
      product: product,
      prefix: prefix,
      len: len,
      data: data,
      hex64: hex64,
      body: body,
      body16: body, /* 兼容旧字段名（不再保证为 16） */
      grouped: grouped,
      code: code
    };
  }

  // 归一化：去短横线 + 转大写（对应二进制 stringByReplacingOccurrencesOfString + uppercaseString）
  function normalize(s) {
    return String(s == null ? '' : s).replace(/-/g, '').toUpperCase();
  }

  /* 从输入码解析数据段长度：优先按 "-" 分段（第 3 段起为数据段）；
   * 整串无短横线时尝试剥掉「前缀+产品代号」后取剩余长度。解析不出返回 0。 */
  function bodyLenOf(code, prefix, product) {
    var s = String(code == null ? '' : code).trim();
    if (!s) return 0;
    var parts = s.split('-');
    if (parts.length >= 3) return parts.slice(2).join('').length;
    var norm = normalize(s);
    var head = normalize(prefix + product);
    if (head && norm.indexOf(head) === 0 && norm.length > head.length) return norm.length - head.length;
    return 0;
  }

  function verify(udid, code, opts) {
    opts = opts || {};
    var r = compute(udid, opts);
    /* 长度自适应：按输入码自身的数据段长度计算期望值并整体比对，
     * 任意长度生成的码都能验证；解析不出长度时退回当前设置长度。 */
    var blen = bodyLenOf(code, r.prefix, r.product);
    var rMatch = blen >= MIN_LEN ? compute(udid, merge(opts, { len: blen })) : null;
    var expected = rMatch || r;

    var inputNorm = normalize(code);
    var expectedNorm = normalize(expected.code);
    return {
      ok: inputNorm === expectedNorm && inputNorm.length > 0,
      result: r,
      expectedCode: expected.code,
      inputNorm: inputNorm,
      expectedNorm: expectedNorm,
      bodyLen: blen,
      lenAdaptive: !!rMatch && blen !== r.len
    };
  }

  function merge(base, extra) {
    var out = {};
    for (var k in base) if (Object.prototype.hasOwnProperty.call(base, k)) out[k] = base[k];
    for (var j in extra) if (Object.prototype.hasOwnProperty.call(extra, j)) out[j] = extra[j];
    return out;
  }

  global.Keygen = {
    KEY: KEY,
    DEFAULTS: DEFAULTS,
    MIN_LEN: MIN_LEN,
    MAX_LEN: MAX_LEN,
    compute: compute,
    normalize: normalize,
    verify: verify,
    groupHex: groupHex,
    clampLen: clampLen,
    getLen: getLen,
    setLen: setLen,
    bodyLenOf: bodyLenOf
  };
})(window);
