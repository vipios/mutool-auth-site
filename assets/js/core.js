/*
 * core.js — 数据层（localStorage）+ 用户认证 + 通用 UI 工具
 * 演示环境：全部数据仅存于浏览器 localStorage，属前端演示级认证。
 */
(function (global) {
  'use strict';

  var LS = {
    USERS: 'mutool_users',
    SESSION: 'mutool_session',
    CODES: 'mutool_codes',
    LOGS: 'mutool_logs'
  };

  /* ---------- 底层读写 ---------- */

  function read(key, fallback) {
    try {
      var raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) {
      return fallback;
    }
  }

  function write(key, val) {
    localStorage.setItem(key, JSON.stringify(val));
  }

  function uid(prefix) {
    return (prefix || 'id') + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }

  function nowISO() {
    return new Date().toISOString();
  }

  function pad(n) { return n < 10 ? '0' + n : '' + n; }

  function fmtTime(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  function todayStr() {
    var d = new Date();
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }

  function daysAgoStr(n) {
    var d = new Date();
    d.setDate(d.getDate() - n);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }

  /* ---------- 种子数据 ---------- */

  function seed() {
    if (read(LS.USERS, null)) return;

    var saltAdmin = 'a1f3';
    var admin = {
      id: uid('u'),
      username: 'admin',
      nickname: '管理员',
      salt: saltAdmin,
      passHash: HMAC.sha256Hex(saltAdmin + ':' + 'Admin@123'),
      role: 'admin',
      createdAt: daysAgoStr(9) + 'T09:00:00.000Z',
      lastLoginAt: null
    };
    var demoUser = {
      id: uid('u'),
      username: 'tester',
      nickname: '测试员',
      salt: 'b7c2',
      passHash: HMAC.sha256Hex('b7c2' + ':' + 'test123456'),
      role: 'user',
      createdAt: daysAgoStr(3) + 'T11:20:00.000Z',
      lastLoginAt: null
    };
    write(LS.USERS, [admin, demoUser]);

    // 演示授权记录：覆盖最近 7 天，便于仪表盘图表展示
    var demoUdids = [
      '00008020-001A2C3E1E44801E',
      '00008110-000925561E80801E',
      '00008030-001A1D2E4C44801E',
      '00008020-002C5A8B12C44802E',
      '00008033-000A1234B1C44801E'
    ];
    var codes = [];
    var logs = [];
    for (var i = 0; i < 5; i++) {
      var day = daysAgoStr(6 - i);
      codes.push({
        id: uid('c'),
        type: 'gen',
        udid: demoUdids[i],
        code: (function (udid) {
          var h = HMAC.hmacSha256Hex('MuziSource-Auth-2026-v1-Secret-Key', 'com.muzi.mutool|' + udid).toUpperCase();
          var b = h.substring(0, 16);
          return 'MUZI-MUTOOL-' + b.substring(0, 4) + '-' + b.substring(4, 8) + '-' + b.substring(8, 12) + '-' + b.substring(12, 16);
        })(demoUdids[i]),
        bundle: 'com.muzi.mutool',
        operator: i % 2 === 0 ? 'admin' : 'tester',
        note: i === 0 ? '文档示例向量' : '',
        createdAt: day + 'T1' + i + ':24:00.000Z'
      });
      logs.push({
        id: uid('l'),
        type: 'gen',
        udid: demoUdids[i],
        code: codes[i].code,
        result: 'ok',
        operator: codes[i].operator,
        createdAt: codes[i].createdAt
      });
      if (i < 3) {
        logs.push({
          id: uid('l'),
          type: 'verify',
          udid: demoUdids[i],
          code: codes[i].code,
          result: i === 2 ? 'fail' : 'ok',
          operator: 'admin',
          createdAt: day + 'T15:0' + i + ':00.000Z'
        });
      }
    }
    write(LS.CODES, codes);
    write(LS.LOGS, logs);
  }

  /* ---------- 用户 ---------- */

  var Store = {
    keys: LS,
    users: function () { return read(LS.USERS, []); },
    saveUsers: function (u) { write(LS.USERS, u); },
    codes: function () { return read(LS.CODES, []); },
    saveCodes: function (c) { write(LS.CODES, c); },
    logs: function () { return read(LS.LOGS, []); },
    saveLogs: function (l) { write(LS.LOGS, l); },
    session: function () { return read(LS.SESSION, null); },
    setSession: function (s) { write(LS.SESSION, s); },
    clearSession: function () { localStorage.removeItem(LS.SESSION); },
    findUser: function (username) {
      var list = this.users();
      for (var i = 0; i < list.length; i++) if (list[i].username === username) return list[i];
      return null;
    },
    addLog: function (entry) {
      var logs = this.logs();
      entry.id = uid('l');
      entry.createdAt = nowISO();
      logs.unshift(entry);
      if (logs.length > 500) logs.length = 500;
      this.saveLogs(logs);
    }
  };

  /* ---------- 认证 ---------- */

  var Auth = {
    current: function () {
      var s = Store.session();
      if (!s) return null;
      var u = Store.findUser(s.username);
      return u || null;
    },
    isAdmin: function () {
      var u = this.current();
      return !!u && u.role === 'admin';
    },
    login: function (username, password) {
      var u = Store.findUser((username || '').trim());
      if (!u) return { ok: false, error: '用户不存在' };
      if (HMAC.sha256Hex(u.salt + ':' + password) !== u.passHash) return { ok: false, error: '密码错误' };
      u.lastLoginAt = nowISO();
      var list = Store.users();
      for (var i = 0; i < list.length; i++) if (list[i].username === u.username) list[i] = u;
      Store.saveUsers(list);
      Store.setSession({ username: u.username, loginAt: nowISO() });
      return { ok: true, user: u };
    },
    register: function (username, nickname, password) {
      username = (username || '').trim();
      if (Store.findUser(username)) return { ok: false, error: '用户名已被注册' };
      var salt = Math.random().toString(36).slice(2, 8);
      var u = {
        id: uid('u'),
        username: username,
        nickname: (nickname || '').trim() || username,
        salt: salt,
        passHash: HMAC.sha256Hex(salt + ':' + password),
        role: 'user',
        createdAt: nowISO(),
        lastLoginAt: null
      };
      var list = Store.users();
      list.push(u);
      Store.saveUsers(list);
      Store.setSession({ username: u.username, loginAt: nowISO() });
      return { ok: true, user: u };
    },
    logout: function () {
      Store.clearSession();
    },
    updateNickname: function (username, nickname) {
      var list = Store.users();
      for (var i = 0; i < list.length; i++) {
        if (list[i].username === username) {
          list[i].nickname = (nickname || '').trim() || list[i].username;
          Store.saveUsers(list);
          return list[i];
        }
      }
      return null;
    },
    changePassword: function (username, oldPwd, newPwd) {
      var list = Store.users();
      for (var i = 0; i < list.length; i++) {
        if (list[i].username === username) {
          if (HMAC.sha256Hex(list[i].salt + ':' + oldPwd) !== list[i].passHash) return { ok: false, error: '原密码错误' };
          var salt = Math.random().toString(36).slice(2, 8);
          list[i].salt = salt;
          list[i].passHash = HMAC.sha256Hex(salt + ':' + newPwd);
          Store.saveUsers(list);
          return { ok: true };
        }
      }
      return { ok: false, error: '用户不存在' };
    }
  };

  /* ---------- UI 工具 ---------- */

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  var ICONS = {
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>',
    x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>',
    warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>',
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>',
    plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></svg>',
    logout: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>',
    menu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h18M3 6h18M3 18h18"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
    key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
    grid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/></svg>',
    list: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg>',
    users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    book: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    activity: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
    cpu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></svg>',
    hash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9h16M4 15h16M10 3L8 21M16 3l-2 18"/></svg>',
    file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>'
  };

  function toast(msg, type) {
    type = type || 'info';
    var root = $('#toast-root') || (function () {
      var d = document.createElement('div');
      d.id = 'toast-root';
      document.body.appendChild(d);
      return d;
    })();
    var el = document.createElement('div');
    el.className = 'toast ' + type;
    var icon = type === 'ok' ? ICONS.check : type === 'err' ? ICONS.x : ICONS.info;
    el.innerHTML = icon + '<span>' + escapeHtml(msg) + '</span>';
    root.appendChild(el);
    setTimeout(function () {
      el.classList.add('leaving');
      setTimeout(function () { el.remove(); }, 220);
    }, 2600);
  }

  function copyText(text, done) {
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) {}
      ta.remove();
      if (done) done();
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { if (done) done(); }, fallback);
    } else {
      fallback();
    }
  }

  function confirmModal(opts) {
    var root = $('#modal-root');
    root.innerHTML =
      '<div class="modal">' +
      '<div class="m-title">' + escapeHtml(opts.title || '确认操作') + '</div>' +
      '<div class="m-body">' + (opts.body || '') + '</div>' +
      '<div class="m-actions">' +
      '<button class="btn btn-default" data-act="cancel">' + escapeHtml(opts.cancelText || '取消') + '</button>' +
      '<button class="btn ' + (opts.danger ? 'btn-primary' : 'btn-primary') + '" data-act="ok" style="' + (opts.danger ? 'background:var(--danger)' : '') + '">' + escapeHtml(opts.okText || '确认') + '</button>' +
      '</div></div>';
    root.classList.add('open');
    function close() { root.classList.remove('open'); root.innerHTML = ''; }
    $('[data-act="cancel"]', root).onclick = close;
    $('[data-act="ok"]', root).onclick = function () { close(); if (opts.onOk) opts.onOk(); };
    root.onclick = function (e) { if (e.target === root) close(); };
  }

  function promptModal(opts) {
    var root = $('#modal-root');
    root.innerHTML =
      '<div class="modal">' +
      '<div class="m-title">' + escapeHtml(opts.title || '输入') + '</div>' +
      '<div class="m-body">' + escapeHtml(opts.body || '') +
      '<input class="input" id="modal-prompt-input" placeholder="' + escapeHtml(opts.placeholder || '') + '" value="' + escapeHtml(opts.value || '') + '">' +
      '</div>' +
      '<div class="m-actions">' +
      '<button class="btn btn-default" data-act="cancel">取消</button>' +
      '<button class="btn btn-primary" data-act="ok">' + escapeHtml(opts.okText || '确认') + '</button>' +
      '</div></div>';
    root.classList.add('open');
    var input = $('#modal-prompt-input', root);
    input.focus();
    input.select();
    function close() { root.classList.remove('open'); root.innerHTML = ''; }
    function ok() { var v = input.value; close(); if (opts.onOk) opts.onOk(v); }
    $('[data-act="cancel"]', root).onclick = close;
    $('[data-act="ok"]', root).onclick = ok;
    input.onkeydown = function (e) { if (e.key === 'Enter') ok(); };
    root.onclick = function (e) { if (e.target === root) close(); };
  }

  function avatarColor(name) {
    var colors = ['#4f46e5', '#7c3aed', '#0d9488', '#dc2626', '#b45309', '#0369a1'];
    var h = 0;
    for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    return colors[h % colors.length];
  }

  seed();

  global.UI = { $: $, $$: $$, escapeHtml: escapeHtml, toast: toast, copyText: copyText, confirmModal: confirmModal, promptModal: promptModal, avatarColor: avatarColor, ICONS: ICONS };
  global.Store = Store;
  global.Auth = Auth;
  global.Fmt = { uid: uid, nowISO: nowISO, fmtTime: fmtTime, todayStr: todayStr, daysAgoStr: daysAgoStr };
})(window);
