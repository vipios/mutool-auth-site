/*
 * keygen.js — 授权码算法封装
 * 1:1 复刻 MUtool (roothide) 2.2.18 授权机制（见《授权机制可提取内容.md》）：
 *
 *   data   = "<BundleID>|<UDID>"                    如 com.muzi.mutool|00008020-...
 *   mac    = HMAC-SHA256(KEY, data)                 KEY = MuziSource-Auth-2026-v1-Secret-Key
 *   hex    = 大写十六进制（64 字符）
 *   截取   = hex 前 16 字符
 *   分组   = 前 16 字符按 4 字分组，"-" 连接        → AAAA-BBBB-CCCC-DDDD
 *   最终   = "MUZI-" + 产品代号 + "-" + 分组        → MUZI-MUTOOL-AAAA-BBBB-CCCC-DDDD
 *
 * 对拍向量：UDID 00008020-001A2C3E1E44801E → MUZI-MUTOOL-F33A-5853-E382-290E
 */
(function (global) {
  'use strict';

  var KEY = 'MuziSource-Auth-2026-v1-Secret-Key';
  var DEFAULTS = {
    bundle: 'com.muzi.mutool',
    product: 'MUTOOL',
    prefix: 'MUZI'
  };

  function compute(udid, opts) {
    opts = opts || {};
    var bundle = (opts.bundle || DEFAULTS.bundle).trim();
    var product = (opts.product || DEFAULTS.product).trim().toUpperCase();
    var prefix = (opts.prefix || DEFAULTS.prefix).trim().toUpperCase();
    udid = (udid || '').trim();

    var data = bundle + '|' + udid;
    var hex64 = HMAC.hmacSha256Hex(KEY, data).toUpperCase();
    var body16 = hex64.substring(0, 16);
    var grouped = body16.substring(0, 4) + '-' + body16.substring(4, 8) + '-' + body16.substring(8, 12) + '-' + body16.substring(12, 16);
    var code = prefix + '-' + product + '-' + grouped;

    return {
      udid: udid,
      bundle: bundle,
      product: product,
      prefix: prefix,
      data: data,
      hex64: hex64,
      body16: body16,
      grouped: grouped,
      code: code
    };
  }

  // 归一化：去短横线 + 转大写（对应二进制 stringByReplacingOccurrencesOfString + uppercaseString）
  function normalize(s) {
    return String(s == null ? '' : s).replace(/-/g, '').toUpperCase();
  }

  function verify(udid, code, opts) {
    var r = compute(udid, opts);
    var expectedCode = r.code;
    var inputNorm = normalize(code);
    var expectedNorm = normalize(expectedCode);
    return {
      ok: inputNorm === expectedNorm && inputNorm.length > 0,
      result: r,
      expectedCode: expectedCode,
      inputNorm: inputNorm,
      expectedNorm: expectedNorm
    };
  }

  global.Keygen = {
    KEY: KEY,
    DEFAULTS: DEFAULTS,
    compute: compute,
    normalize: normalize,
    verify: verify
  };
})(window);
