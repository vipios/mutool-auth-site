/*
 * app.js — MUtool 授权管理平台 · 控制台主逻辑
 * 页面：仪表盘 / 授权码生成 / 授权码验证 / 授权记录 / 用户管理 / 机制文档 / 个人设置
 */
(function () {
  'use strict';
  var $ = UI.$, $$ = UI.$$, escapeHtml = UI.escapeHtml, ICONS = UI.ICONS;

  /* ---------- 登录守卫 ---------- */
  if (!Auth.current()) {
    location.replace('index.html');
    return;
  }

  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function dateOf(iso) {
    var d = new Date(iso);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }

  /* ---------- 导航配置 ---------- */
  var NAV = [
    { group: '总览' },
    { route: 'dashboard', label: '仪表盘', icon: 'grid' },
    { group: '授权工具' },
    { route: 'generator', label: '授权码生成', icon: 'key' },
    { route: 'verifier', label: '授权码验证', icon: 'shield' },
    { route: 'records', label: '授权记录', icon: 'list' },
    { group: '系统' },
    { route: 'users', label: '用户管理', icon: 'users', admin: true },
    { route: 'docs', label: '机制文档', icon: 'book' },
    { route: 'settings', label: '个人设置', icon: 'settings' }
  ];
  var TITLES = {
    dashboard: ['仪表盘', '授权机制运行态势总览'],
    generator: ['授权码生成', '按原版算法由 UDID 离线派生授权码'],
    verifier: ['授权码验证', '归一化比对，实时判定授权码有效性'],
    records: ['授权记录', '生成与验证操作审计日志'],
    users: ['用户管理', '平台账号与角色权限'],
    docs: ['机制文档', 'MUtool 2.2.18 授权机制逆向分析整理'],
    settings: ['个人设置', '账号信息与密码管理']
  };

  function renderNav() {
    var html = '';
    NAV.forEach(function (item) {
      if (item.group) { html += '<div class="nav-group">' + item.group + '</div>'; return; }
      if (item.admin && !Auth.isAdmin()) return;
      html += '<a href="#' + item.route + '" data-route="' + item.route + '">' + ICONS[item.icon] + '<span>' + item.label + '</span></a>';
    });
    $('#s-nav').innerHTML = html;
  }

  function renderUserChip() {
    var u = Auth.current();
    $('#user-chip').innerHTML =
      '<span class="avatar" style="background:' + UI.avatarColor(u.username) + '">' + escapeHtml(u.nickname.charAt(0).toUpperCase()) + '</span>' +
      '<div><div class="u-name">' + escapeHtml(u.nickname) + '</div>' +
      '<div class="u-role">' + escapeHtml(u.username) + (u.role === 'admin' ? ' · 管理员' : ' · 用户') + '</div></div>';
  }

  function closeSidebar() {
    $('#sidebar').classList.remove('open');
    $('#sidebar-mask').classList.remove('show');
  }

  /* ---------- 路由 ---------- */
  function currentRoute() {
    var h = (location.hash || '').replace('#', '');
    if (!TITLES[h]) h = 'dashboard';
    if (h === 'users' && !Auth.isAdmin()) h = 'dashboard';
    return h;
  }

  var PAGES = {};

  function render() {
    var route = currentRoute();
    $$('#s-nav a').forEach(function (a) { a.classList.toggle('active', a.dataset.route === route); });
    $('#page-title').textContent = TITLES[route][0];
    $('#page-sub').textContent = TITLES[route][1];
    renderUserChip();
    closeSidebar();
    PAGES[route]();
    window.scrollTo(0, 0);
  }

  window.addEventListener('hashchange', render);

  /* ---------- 通用小部件 ---------- */
  function statCard(bg, color, icon, num, label) {
    return '<div class="stat-card"><span class="st-icon" style="background:' + bg + ';color:' + color + '">' + icon + '</span>' +
      '<div><div class="st-num">' + num + '</div><div class="st-label">' + label + '</div></div></div>';
  }

  function buildChart(days) {
    var W = 560, H = 200, padL = 30, padB = 26, padT = 14;
    var max = 2;
    days.forEach(function (d) { max = Math.max(max, d.gen, d.verify); });
    max = Math.ceil(max / 2) * 2;
    var innerW = W - padL - 8, innerH = H - padT - padB;
    var groupW = innerW / days.length;
    var barW = Math.min(15, groupW / 3.2);
    var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;height:auto;display:block">';
    for (var g = 0; g <= 4; g++) {
      var y = padT + innerH - (innerH * g / 4);
      svg += '<line x1="' + padL + '" y1="' + y + '" x2="' + (W - 4) + '" y2="' + y + '" stroke="#eef1f7"/>';
      svg += '<text x="' + (padL - 6) + '" y="' + (y + 3.5) + '" text-anchor="end" font-size="10" fill="#97a1b3">' + Math.round(max * g / 4) + '</text>';
    }
    days.forEach(function (d, i) {
      var gx = padL + groupW * i;
      var genH = innerH * d.gen / max, verH = innerH * d.verify / max;
      var x1 = gx + groupW / 2 - barW - 3, x2 = gx + groupW / 2 + 3;
      svg += '<rect x="' + x1 + '" y="' + (padT + innerH - genH) + '" width="' + barW + '" height="' + Math.max(genH, 2) + '" rx="3" fill="#4f46e5"><title>' + d.label + ' 生成 ' + d.gen + '</title></rect>';
      svg += '<rect x="' + x2 + '" y="' + (padT + innerH - verH) + '" width="' + barW + '" height="' + Math.max(verH, 2) + '" rx="3" fill="#0d9488"><title>' + d.label + ' 验证 ' + d.verify + '</title></rect>';
      svg += '<text x="' + (gx + groupW / 2) + '" y="' + (H - 8) + '" text-anchor="middle" font-size="10.5" fill="#97a1b3">' + d.label + '</text>';
    });
    return svg + '</svg>';
  }

  function codeDisplayHtml(code) {
    var parts = String(code).split('-');
    var head = parts.slice(0, 2).join('-') + '-';
    var tail = parts.slice(2).join('-');
    return '<div class="code-display"><div class="cd-text"><span class="cd-seg">' + escapeHtml(head) + '</span><span class="cd-tail">' + escapeHtml(tail) + '</span></div>' +
      '<button class="btn btn-default btn-sm" data-copy="' + escapeHtml(code) + '">' + ICONS.copy + ' 复制</button></div>';
  }

  function pipeStep(idx, name, code, val, final) {
    return '<div class="pipe-step' + (final ? ' final' : '') + '"><span class="p-idx">' + idx + '</span>' +
      '<div class="p-body"><div class="p-name">' + name + (code ? ' <code>' + code + '</code>' : '') + '</div>' +
      '<div class="p-val">' + escapeHtml(val) + '</div></div></div>';
  }

  function pipelineHtml(r) {
    return '<div class="pipeline">' +
      pipeStep(1, 'HMAC 数据串', 'bundle|udid', r.data) +
      pipeStep(2, 'HMAC-SHA256', 'Key = ' + escapeHtml(Keygen.KEY), r.hex64) +
      pipeStep(3, '截取前 16 字符', 'substringToIndex:16', r.body16) +
      pipeStep(4, '按 4 字分 4 组', 'AAAA-BBBB-CCCC-DDDD', r.grouped) +
      pipeStep(5, '拼接最终格式', 'MUZI-&lt;product&gt;-&lt;grouped&gt;', r.code, true) +
      '</div>';
  }

  function saveGenEntry(r, note) {
    var u = Auth.current();
    var list = Store.codes();
    list.unshift({
      id: Fmt.uid('c'), type: 'gen', udid: r.udid, code: r.code,
      bundle: r.bundle, operator: u.username, note: note || '', createdAt: Fmt.nowISO()
    });
    Store.saveCodes(list);
    Store.addLog({ type: 'gen', udid: r.udid, code: r.code, result: 'ok', operator: u.username });
  }

  /* 全局复制按钮委托 */
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-copy]');
    if (!btn) return;
    UI.copyText(btn.dataset.copy, function () { UI.toast('已复制：' + btn.dataset.copy, 'ok'); });
  });

  /* ============================================================
     仪表盘
     ============================================================ */
  PAGES.dashboard = function () {
    var u = Auth.current();
    var codes = Store.codes();
    var logs = Store.logs();
    var users = Store.users();
    var today = Fmt.todayStr();

    var todayGen = 0;
    codes.forEach(function (c) { if (dateOf(c.createdAt) === today) todayGen++; });
    var verifyCount = logs.filter(function (l) { return l.type === 'verify'; }).length;
    var verifyOk = logs.filter(function (l) { return l.type === 'verify' && l.result === 'ok'; }).length;

    var days = [];
    for (var i = 6; i >= 0; i--) {
      var ds = Fmt.daysAgoStr(i);
      var d = new Date(ds + 'T00:00:00');
      days.push({
        label: (d.getMonth() + 1) + '/' + d.getDate(),
        gen: codes.filter(function (c) { return dateOf(c.createdAt) === ds; }).length,
        verify: logs.filter(function (l) { return l.type === 'verify' && dateOf(l.createdAt) === ds; }).length
      });
    }

    var hour = new Date().getHours();
    var greet = hour < 6 ? '凌晨好' : hour < 12 ? '早上好' : hour < 14 ? '中午好' : hour < 18 ? '下午好' : '晚上好';

    var recent = logs.slice(0, 8);
    var activityHtml = recent.length ? recent.map(function (l) {
      var isGen = l.type === 'gen';
      return '<div class="activity-item">' +
        '<span class="a-icon" style="background:' + (isGen ? 'var(--primary-soft)' : 'var(--teal-soft)') + ';color:' + (isGen ? 'var(--primary)' : 'var(--teal)') + '">' + (isGen ? ICONS.key : ICONS.shield) + '</span>' +
        '<div class="a-main"><div class="a-title">' + (isGen ? '生成授权码' : '验证授权码') + ' <span class="cell-mono" style="color:var(--text-2)">' + escapeHtml(l.code) + '</span></div>' +
        '<div class="a-time">' + Fmt.fmtTime(l.createdAt) + ' · ' + escapeHtml(l.operator) + '</div></div>' +
        '<span class="badge ' + (l.result === 'ok' ? 'badge-ok' : 'badge-fail') + '">' + (l.result === 'ok' ? '成功' : '未通过') + '</span>' +
        '</div>';
    }).join('') : '<div class="empty">' + ICONS.activity + '<p>暂无操作记录</p></div>';

    $('#content').innerHTML =
      '<div class="page-head"><h2>' + greet + '，' + escapeHtml(u.nickname) + '</h2><p>今天是 ' + today + '，授权机制运行正常。</p></div>' +
      '<div class="grid grid-4" style="margin-bottom:16px">' +
      statCard('var(--primary-soft)', 'var(--primary)', ICONS.key, todayGen, '今日生成授权码') +
      statCard('var(--violet-soft)', 'var(--violet)', ICONS.hash, codes.length, '累计生成授权码') +
      statCard('var(--teal-soft)', 'var(--teal)', ICONS.shield, verifyCount, '累计验证次数') +
      statCard('#eef1f7', 'var(--text-2)', ICONS.users, users.length, '平台注册用户') +
      '</div>' +
      '<div class="grid grid-sidebar">' +
      '<div class="card"><div class="card-pad"><div class="card-title">近 7 天授权操作<span class="sub">生成 / 验证</span></div>' +
      '<div class="chart-box">' + buildChart(days) + '</div>' +
      '<div class="chart-legend"><span><i style="background:#4f46e5"></i>生成</span><span><i style="background:#0d9488"></i>验证</span>' +
      '<span style="margin-left:auto">验证通过率 ' + (verifyCount ? Math.round(verifyOk / verifyCount * 100) : 100) + '%</span></div>' +
      '</div></div>' +
      '<div>' +
      '<div class="card card-pad" style="margin-bottom:16px"><div class="card-title">快捷操作</div>' +
      '<div class="quick-actions">' +
      '<button class="quick-action" data-go="generator"><span class="q-icon" style="background:var(--primary-soft);color:var(--primary)">' + ICONS.key + '</span><div><b>生成授权码</b><span>输入 UDID 立即派生</span></div></button>' +
      '<button class="quick-action" data-go="verifier"><span class="q-icon" style="background:var(--teal-soft);color:var(--teal)">' + ICONS.shield + '</span><div><b>验证授权码</b><span>比对 UDID 与授权码</span></div></button>' +
      '</div></div>' +
      '<div class="card card-pad"><div class="card-title">最近操作</div><div class="activity-list">' + activityHtml + '</div></div>' +
      '</div>' +
      '</div>';

    $$('[data-go]').forEach(function (b) { b.onclick = function () { location.hash = b.dataset.go; }; });
  };

  /* ============================================================
     授权码生成
     ============================================================ */
  PAGES.generator = function () {
    var lastR = null, lastNote = '';

    $('#content').innerHTML =
      '<div class="page-head"><h2>授权码生成</h2><p>流水线：HMAC-SHA256(Key, BundleID|UDID) → 大写十六进制 → 前 16 字符 → 按 4 字分 4 组 → MUZI-&lt;产品&gt;-AAAA-BBBB-CCCC-DDDD。</p></div>' +
      '<div class="card card-pad">' +
      '<div class="tabs"><button class="active" data-tab="single">单个生成</button><button data-tab="batch">批量生成</button></div>' +

      '<div id="tab-single">' +
      '<div class="grid grid-2">' +
      '<div class="field"><label class="field-label">设备 UDID<span class="req">*</span></label>' +
      '<input class="input mono" id="g-udid" placeholder="例如 00008020-001A2C3E1E44801E">' +
      '<div class="field-error"></div>' +
      '<div class="field-hint"><button class="btn-link" id="g-fill-demo" type="button">填入文档示例 UDID</button></div></div>' +
      '<div class="field"><label class="field-label">备注</label>' +
      '<input class="input" id="g-note" placeholder="选填，例如客户名称 / 设备用途"></div>' +
      '</div>' +
      '<div class="grid grid-3">' +
      '<div class="field"><label class="field-label">Bundle ID</label><input class="input mono" id="g-bundle" value="' + Keygen.DEFAULTS.bundle + '"></div>' +
      '<div class="field"><label class="field-label">产品代号</label><input class="input mono" id="g-product" value="' + Keygen.DEFAULTS.product + '"></div>' +
      '<div class="field"><label class="field-label">授权码前缀</label><input class="input mono" id="g-prefix" value="' + Keygen.DEFAULTS.prefix + '"></div>' +
      '</div>' +
      '<div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap">' +
      '<button class="btn btn-primary" id="g-run">' + ICONS.key + ' 生成授权码</button>' +
      '<label style="font-size:13px;color:var(--text-2);display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none">' +
      '<input type="checkbox" id="g-autosave" checked> 自动保存到授权记录</label>' +
      '</div>' +
      '<div id="g-result"></div>' +
      '</div>' +

      '<div id="tab-batch" style="display:none">' +
      '<div class="field"><label class="field-label">UDID 列表<span class="req">*</span></label>' +
      '<textarea class="input mono" id="b-udids" rows="6" placeholder="每行一个 UDID，例如：&#10;00008020-001A2C3E1E44801E&#10;00008110-000925561E80801E"></textarea>' +
      '<div class="field-hint">单次最多 200 行；Bundle / 产品代号 / 前缀与左侧「单个生成」中的设置保持一致（修改后请切回单个页签查看当前值）。</div></div>' +
      '<button class="btn btn-primary" id="b-run">批量生成</button>' +
      '<div id="b-result" style="margin-top:16px"></div>' +
      '</div>' +
      '</div>';

    $$('.tabs button').forEach(function (btn) {
      btn.onclick = function () {
        $$('.tabs button').forEach(function (b) { b.classList.toggle('active', b === btn); });
        $('#tab-single').style.display = btn.dataset.tab === 'single' ? '' : 'none';
        $('#tab-batch').style.display = btn.dataset.tab === 'batch' ? '' : 'none';
      };
    });

    $('#g-fill-demo').onclick = function () {
      $('#g-udid').value = '00008020-001A2C3E1E44801E';
      $('#g-udid').focus();
    };

    $('#g-run').onclick = function () {
      var input = $('#g-udid');
      var field = input.closest('.field');
      field.classList.remove('has-error');
      var udid = input.value.trim();
      if (!udid) {
        field.classList.add('has-error');
        field.querySelector('.field-error').textContent = '请输入 UDID';
        return;
      }
      var opts = { bundle: $('#g-bundle').value, product: $('#g-product').value, prefix: $('#g-prefix').value };
      lastR = Keygen.compute(udid, opts);
      lastNote = $('#g-note').value.trim();
      var saved = $('#g-autosave').checked;
      if (saved) saveGenEntry(lastR, lastNote);

      $('#g-result').innerHTML =
        '<div class="card result-card card-pad">' +
        '<div class="card-title">生成结果 <span class="sub" id="g-save-state">' + (saved ? '已保存到授权记录' : '未保存') + '</span></div>' +
        codeDisplayHtml(lastR.code) +
        '<div style="font-size:12px;color:var(--text-3);margin:10px 0 14px">有效长度 12 位十六进制（48 bit）· 绑定 UDID <span class="cell-mono">' + escapeHtml(udid) + '</span></div>' +
        pipelineHtml(lastR) +
        (saved ? '' : '<div style="margin-top:14px"><button class="btn btn-default" id="g-save">保存到授权记录</button></div>') +
        '</div>';

      if (!saved) {
        $('#g-save').onclick = function () {
          saveGenEntry(lastR, lastNote);
          $('#g-save-state').textContent = '已保存到授权记录';
          $('#g-save').remove();
          UI.toast('已保存到授权记录', 'ok');
        };
      }
    };

    /* ---- 批量 ---- */
    var batchResults = [];
    $('#b-run').onclick = function () {
      var raw = $('#b-udids').value;
      var lines = raw.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean).slice(0, 200);
      if (!lines.length) { UI.toast('请输入至少一个 UDID', 'err'); return; }
      var opts = { bundle: $('#g-bundle').value, product: $('#g-product').value, prefix: $('#g-prefix').value };
      batchResults = lines.map(function (udid) { return Keygen.compute(udid, opts); });

      var rows = batchResults.map(function (r, i) {
        return '<tr><td class="cell-mono" style="width:36px;color:var(--text-3)">' + (i + 1) + '</td>' +
          '<td class="cell-mono">' + escapeHtml(r.udid) + '</td>' +
          '<td class="cell-mono" style="font-weight:600">' + escapeHtml(r.code) + '</td>' +
          '<td><div class="cell-actions"><button class="btn-link" data-copy="' + escapeHtml(r.code) + '">复制</button></div></td></tr>';
      }).join('');

      $('#b-result').innerHTML =
        '<div class="card"><div class="card-pad" style="padding-bottom:0"><div class="card-title">批量结果（' + batchResults.length + ' 条）' +
        '<button class="btn btn-default btn-sm" id="b-save-all">全部保存到授权记录</button></div></div>' +
        '<div class="table-wrap"><table class="table"><thead><tr><th></th><th>UDID</th><th>授权码</th><th style="text-align:right">操作</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div></div>';

      $('#b-save-all').onclick = function () {
        batchResults.forEach(function (r) { saveGenEntry(r, '批量生成'); });
        UI.toast('已保存 ' + batchResults.length + ' 条授权记录', 'ok');
        $('#b-save-all').remove();
      };
    };
  };

  /* ============================================================
     授权码验证
     ============================================================ */
  PAGES.verifier = function () {
    $('#content').innerHTML =
      '<div class="page-head"><h2>授权码验证</h2><p>复刻原版归一化比对：去除短横线、统一大写后逐字符比较（对应二进制 0x9414 处的 isEqualToString）。</p></div>' +
      '<div class="grid grid-sidebar">' +
      '<div class="card card-pad">' +
      '<div class="field"><label class="field-label">设备 UDID<span class="req">*</span></label>' +
      '<input class="input mono" id="v-udid" placeholder="例如 00008020-001A2C3E1E44801E"><div class="field-error"></div></div>' +
      '<div class="field"><label class="field-label">授权码<span class="req">*</span></label>' +
      '<input class="input mono" id="v-code" placeholder="MUZI-MUTOOL-AAAA-BBBB-CCCC-DDDD" style="letter-spacing:0.06em"><div class="field-error"></div>' +
      '<div class="field-hint">大小写与短横线不敏感，可粘贴任意格式。</div></div>' +
      '<div class="field"><label class="field-label">备注</label><input class="input" id="v-note" placeholder="选填"></div>' +
      '<button class="btn btn-primary" id="v-run">' + ICONS.shield + ' 开始验证</button>' +
      '<div id="v-result"></div>' +
      '</div>' +
      '<div>' +
      '<div class="card card-pad" style="margin-bottom:16px"><div class="card-title">算法参数</div>' +
      '<div class="kv-row"><span class="k">HMAC 密钥</span><span class="v">' + escapeHtml(Keygen.KEY) + '</span></div>' +
      '<div class="kv-row"><span class="k">默认 Bundle</span><span class="v">' + escapeHtml(Keygen.DEFAULTS.bundle) + '</span></div>' +
      '<div class="kv-row"><span class="k">归一化规则</span><span class="v" style="font-family:var(--sans);font-size:12.5px">去 "-" · 转大写</span></div>' +
      '<div class="kv-row"><span class="k">格式</span><span class="v" style="font-family:var(--sans);font-size:12.5px">MUZI-MUTOOL-AAAA-BBBB-CCCC-DDDD</span></div>' +
      '</div>' +
      '<div class="callout warn">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>' +
      '<div><b>已知弱点：</b>该机制密钥硬编码于客户端，授权码可被离线重算；且存在 cfprefsd 信任兜底与单字节 Patch 路径。详见「机制文档」第 6 节。</div>' +
      '</div>' +
      '</div>' +
      '</div>';

    $('#v-run').onclick = function () {
      var udidInput = $('#v-udid'), codeInput = $('#v-code');
      var f1 = udidInput.closest('.field'), f2 = codeInput.closest('.field');
      f1.classList.remove('has-error'); f2.classList.remove('has-error');
      var udid = udidInput.value.trim();
      var code = codeInput.value.trim();
      if (!udid) { f1.classList.add('has-error'); f1.querySelector('.field-error').textContent = '请输入 UDID'; return; }
      if (!code) { f2.classList.add('has-error'); f2.querySelector('.field-error').textContent = '请输入授权码'; return; }

      var res = Keygen.verify(udid, code);
      var u = Auth.current();
      Store.addLog({ type: 'verify', udid: udid, code: code, result: res.ok ? 'ok' : 'fail', operator: u.username });

      $('#v-result').innerHTML =
        '<div class="verify-banner ' + (res.ok ? 'ok' : 'fail') + '">' +
        '<span class="v-icon">' + (res.ok ? ICONS.check : ICONS.x) + '</span>' +
        '<div><b>' + (res.ok ? '验证通过' : '验证未通过') + '</b>' +
        '<span>' + (res.ok ? '该授权码与 UDID 绑定匹配，可视为已授权。' : '授权码与 UDID 不匹配，或格式不正确。') + '</span></div></div>' +
        '<div class="card card-pad" style="margin-top:12px">' +
        '<div class="kv-row"><span class="k">输入授权码</span><span class="v">' + escapeHtml(code) + '</span></div>' +
        '<div class="kv-row"><span class="k">归一化输入</span><span class="v ' + (res.ok ? 'match' : 'mismatch') + '">' + escapeHtml(res.inputNorm || '（空）') + '</span></div>' +
        '<div class="kv-row"><span class="k">期望授权码</span><span class="v">' + escapeHtml(res.expectedCode) + '</span></div>' +
        '<div class="kv-row"><span class="k">归一化期望</span><span class="v ' + (res.ok ? 'match' : 'mismatch') + '">' + escapeHtml(res.expectedNorm) + '</span></div>' +
        '<div class="kv-row"><span class="k">判定</span><span class="v ' + (res.ok ? 'match' : 'mismatch') + '" style="font-family:var(--sans)">' + (res.ok ? '相等 → 通过' : '不相等 → 未通过') + '</span></div>' +
        '</div>';
    };
  };

  /* ============================================================
     授权记录
     ============================================================ */
  PAGES.records = function () {
    var state = { q: '', type: 'all' };
    var isAdmin = Auth.isAdmin();

    function allEntries() {
      var arr = [];
      Store.codes().forEach(function (c) {
        arr.push({ id: c.id, src: 'codes', type: 'gen', createdAt: c.createdAt, udid: c.udid, code: c.code, operator: c.operator, note: c.note || '', result: 'ok' });
      });
      Store.logs().forEach(function (l) {
        if (l.type !== 'verify') return;
        arr.push({ id: l.id, src: 'logs', type: 'verify', createdAt: l.createdAt, udid: l.udid, code: l.code, operator: l.operator, note: '', result: l.result });
      });
      arr.sort(function (a, b) { return a.createdAt < b.createdAt ? 1 : -1; });
      return arr;
    }

    function filtered(entries) {
      var q = state.q.toLowerCase();
      return entries.filter(function (e) {
        if (state.type !== 'all' && e.type !== state.type) return false;
        if (!q) return true;
        return (e.udid + ' ' + e.code + ' ' + e.operator + ' ' + (e.note || '')).toLowerCase().indexOf(q) !== -1;
      });
    }

    function rowHtml(e) {
      return '<tr>' +
        '<td style="white-space:nowrap">' + Fmt.fmtTime(e.createdAt) + '</td>' +
        '<td><span class="badge ' + (e.type === 'gen' ? 'badge-gen' : 'badge-verify') + '">' + (e.type === 'gen' ? '生成' : '验证') + '</span></td>' +
        '<td class="cell-mono">' + escapeHtml(e.udid) + '</td>' +
        '<td class="cell-mono" style="font-weight:600">' + escapeHtml(e.code) + '</td>' +
        '<td>' + escapeHtml(e.operator) + '</td>' +
        '<td><span class="badge ' + (e.result === 'ok' ? 'badge-ok' : 'badge-fail') + '">' + (e.result === 'ok' ? '成功' : '未通过') + '</span></td>' +
        '<td class="cell-sub">' + escapeHtml(e.note || '—') + '</td>' +
        '<td><div class="cell-actions">' +
        '<button class="btn-link" data-copy="' + escapeHtml(e.code) + '">复制</button>' +
        '<button class="btn-link danger" data-del="' + e.id + '">删除</button>' +
        '</div></td></tr>';
    }

    function renderTable() {
      var entries = filtered(allEntries());
      var tbody = $('#rec-tbody');
      if (!entries.length) {
        tbody.innerHTML = '<tr><td colspan="8"><div class="empty">' + ICONS.list + '<p>没有符合条件的记录</p></div></td></tr>';
      } else {
        tbody.innerHTML = entries.map(rowHtml).join('');
      }
      $('#rec-count').textContent = entries.length;
      $$('#rec-tbody [data-del]').forEach(function (btn) {
        btn.onclick = function () {
          var id = btn.dataset.del;
          UI.confirmModal({
            title: '删除记录', body: '删除后不可恢复，确认删除该条授权记录？', okText: '删除', danger: true,
            onOk: function () {
              Store.saveCodes(Store.codes().filter(function (c) { return c.id !== id; }));
              Store.saveLogs(Store.logs().filter(function (l) { return l.id !== id; }));
              UI.toast('记录已删除', 'ok');
              renderTable();
            }
          });
        };
      });
    }

    $('#content').innerHTML =
      '<div class="page-head"><h2>授权记录</h2><p>共 <b id="rec-count">0</b> 条记录：授权码生成与验证操作全量审计。</p></div>' +
      '<div class="toolbar">' +
      '<div class="search-box">' + ICONS.search + '<input class="input" id="rec-q" placeholder="搜索 UDID / 授权码 / 操作人 / 备注"></div>' +
      '<select class="select" id="rec-type"><option value="all">全部类型</option><option value="gen">仅生成</option><option value="verify">仅验证</option></select>' +
      '<div class="t-spacer"></div>' +
      '<button class="btn btn-default" id="rec-export">' + ICONS.download + ' 导出 CSV</button>' +
      (isAdmin ? '<button class="btn btn-danger" id="rec-clear">' + ICONS.trash + ' 清空</button>' : '') +
      '</div>' +
      '<div class="card"><div class="table-wrap"><table class="table">' +
      '<thead><tr><th>时间</th><th>类型</th><th>UDID</th><th>授权码</th><th>操作人</th><th>结果</th><th>备注</th><th style="text-align:right">操作</th></tr></thead>' +
      '<tbody id="rec-tbody"></tbody></table></div></div>';

    renderTable();

    var qTimer = null;
    $('#rec-q').oninput = function () {
      clearTimeout(qTimer);
      qTimer = setTimeout(function () { state.q = $('#rec-q').value.trim(); renderTable(); }, 160);
    };
    $('#rec-type').onchange = function () { state.type = $('#rec-type').value; renderTable(); };

    $('#rec-export').onclick = function () {
      var entries = filtered(allEntries());
      if (!entries.length) { UI.toast('没有可导出的记录', 'err'); return; }
      var lines = ['时间,类型,UDID,授权码,操作人,结果,备注'];
      entries.forEach(function (e) {
        var vals = [Fmt.fmtTime(e.createdAt), e.type === 'gen' ? '生成' : '验证', e.udid, e.code, e.operator, e.result === 'ok' ? '成功' : '未通过', e.note || ''];
        lines.push(vals.map(function (v) { return '"' + String(v).replace(/"/g, '""') + '"'; }).join(','));
      });
      var blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = '授权记录_' + Fmt.todayStr() + '.csv';
      document.body.appendChild(a);
      a.click();
      a.remove();
      UI.toast('已导出 ' + entries.length + ' 条记录', 'ok');
    };

    if (isAdmin) {
      $('#rec-clear').onclick = function () {
        UI.confirmModal({
          title: '清空全部记录', body: '将删除所有生成与验证记录（用户账号不受影响），此操作不可恢复。', okText: '全部清空', danger: true,
          onOk: function () {
            Store.saveCodes([]);
            Store.saveLogs([]);
            UI.toast('已清空授权记录', 'ok');
            renderTable();
          }
        });
      };
    }
  };

  /* ============================================================
     用户管理（管理员）
     ============================================================ */
  function updateUser(username, patch) {
    var list = Store.users();
    for (var i = 0; i < list.length; i++) {
      if (list[i].username === username) {
        for (var k in patch) list[i][k] = patch[k];
        break;
      }
    }
    Store.saveUsers(list);
  }

  PAGES.users = function () {
    var self = Auth.current();
    var users = Store.users();
    var adminCount = users.filter(function (u) { return u.role === 'admin'; }).length;

    var rows = users.map(function (t) {
      var isSelf = t.username === self.username;
      return '<tr>' +
        '<td><div style="display:flex;align-items:center;gap:10px">' +
        '<span class="avatar" style="background:' + UI.avatarColor(t.username) + ';width:28px;height:28px;font-size:12px">' + escapeHtml(t.nickname.charAt(0).toUpperCase()) + '</span>' +
        '<div><div style="font-weight:500">' + escapeHtml(t.username) + (isSelf ? ' <span class="cell-sub">（当前账号）</span>' : '') + '</div>' +
        '<div class="cell-sub">' + escapeHtml(t.nickname) + '</div></div></div></td>' +
        '<td><span class="badge ' + (t.role === 'admin' ? 'badge-admin' : 'badge-user') + '">' + (t.role === 'admin' ? '管理员' : '普通用户') + '</span></td>' +
        '<td class="cell-sub" style="white-space:nowrap">' + Fmt.fmtTime(t.createdAt) + '</td>' +
        '<td class="cell-sub" style="white-space:nowrap">' + Fmt.fmtTime(t.lastLoginAt) + '</td>' +
        '<td><div class="cell-actions">' +
        '<button class="btn-link" data-role="' + escapeHtml(t.username) + '">' + (t.role === 'admin' ? '设为普通用户' : '设为管理员') + '</button>' +
        '<button class="btn-link" data-pwd="' + escapeHtml(t.username) + '">重置密码</button>' +
        '<button class="btn-link danger" data-del="' + escapeHtml(t.username) + '">删除</button>' +
        '</div></td></tr>';
    }).join('');

    $('#content').innerHTML =
      '<div class="page-head" style="display:flex;align-items:flex-start;gap:16px">' +
      '<div style="flex:1"><h2>用户管理</h2><p>共 ' + users.length + ' 个账号，其中 ' + adminCount + ' 名管理员。演示环境：密码经加盐 SHA-256 后存于 localStorage。</p></div>' +
      '<button class="btn btn-primary" id="u-new">' + ICONS.plus + ' 新建用户</button>' +
      '</div>' +
      '<div class="card"><div class="table-wrap"><table class="table">' +
      '<thead><tr><th>账号</th><th>角色</th><th>注册时间</th><th>最近登录</th><th style="text-align:right">操作</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div></div>';

    $$('[data-role]').forEach(function (btn) {
      btn.onclick = function () {
        var name = btn.dataset.role;
        if (name === self.username) { UI.toast('不能修改自己的角色', 'err'); return; }
        var target = Store.findUser(name);
        if (!target) return;
        if (target.role === 'admin' && adminCount <= 1) { UI.toast('至少需要保留一名管理员', 'err'); return; }
        updateUser(name, { role: target.role === 'admin' ? 'user' : 'admin' });
        UI.toast(name + ' 已设为' + (target.role === 'admin' ? '普通用户' : '管理员'), 'ok');
        PAGES.users();
      };
    });

    $$('[data-pwd]').forEach(function (btn) {
      btn.onclick = function () {
        var name = btn.dataset.pwd;
        UI.promptModal({
          title: '重置密码', body: '为 ' + escapeHtml(name) + ' 设置新密码（至少 6 位）', placeholder: '新密码', okText: '重置',
          onOk: function (v) {
            if (!v || v.length < 6) { UI.toast('密码至少 6 位', 'err'); return; }
            var salt = Math.random().toString(36).slice(2, 8);
            updateUser(name, { salt: salt, passHash: HMAC.sha256Hex(salt + ':' + v) });
            UI.toast('已重置 ' + name + ' 的密码', 'ok');
          }
        });
      };
    });

    $$('[data-del]').forEach(function (btn) {
      btn.onclick = function () {
        var name = btn.dataset.del;
        if (name === self.username) { UI.toast('不能删除当前登录账号', 'err'); return; }
        var target = Store.findUser(name);
        if (target && target.role === 'admin' && adminCount <= 1) { UI.toast('至少需要保留一名管理员', 'err'); return; }
        UI.confirmModal({
          title: '删除用户', body: '确认删除账号 <b>' + escapeHtml(name) + '</b>？该用户的历史授权记录会保留。', okText: '删除', danger: true,
          onOk: function () {
            Store.saveUsers(Store.users().filter(function (u) { return u.username !== name; }));
            if (Store.session() && Store.session().username === name) Store.clearSession();
            UI.toast('已删除 ' + name, 'ok');
            PAGES.users();
          }
        });
      };
    });

    $('#u-new').onclick = function () {
      UI.promptModal({
        title: '新建用户', body: '设置用户名（3-20 位字母、数字、下划线）', placeholder: '用户名', okText: '下一步',
        onOk: function (name) {
          name = (name || '').trim();
          if (!/^[a-zA-Z0-9_]{3,20}$/.test(name)) { UI.toast('用户名需为 3-20 位字母、数字或下划线', 'err'); return; }
          if (Store.findUser(name)) { UI.toast('用户名已存在', 'err'); return; }
          UI.promptModal({
            title: '设置初始密码', body: '为 ' + escapeHtml(name) + ' 设置初始密码（至少 6 位）', placeholder: '初始密码', okText: '创建',
            onOk: function (pwd) {
              if (!pwd || pwd.length < 6) { UI.toast('密码至少 6 位', 'err'); return; }
              var salt = Math.random().toString(36).slice(2, 8);
              var list = Store.users();
              list.push({
                id: Fmt.uid('u'), username: name, nickname: name, salt: salt,
                passHash: HMAC.sha256Hex(salt + ':' + pwd), role: 'user',
                createdAt: Fmt.nowISO(), lastLoginAt: null
              });
              Store.saveUsers(list);
              UI.toast('用户 ' + name + ' 已创建', 'ok');
              PAGES.users();
            }
          });
        }
      });
    };
  };

  /* ============================================================
     机制文档
     ============================================================ */
  PAGES.docs = function () {
    $('#content').innerHTML = '<div class="card card-pad doc-article">' + DOCS_HTML + '</div>';
  };

  /* ============================================================
     个人设置
     ============================================================ */
  PAGES.settings = function () {
    var u = Auth.current();

    $('#content').innerHTML =
      '<div class="page-head"><h2>个人设置</h2><p>管理账号资料与登录密码。</p></div>' +
      '<div class="settings-grid">' +
      '<div class="card card-pad account-card">' +
      '<div class="ac-head">' +
      '<span class="avatar" style="background:' + UI.avatarColor(u.username) + '">' + escapeHtml(u.nickname.charAt(0).toUpperCase()) + '</span>' +
      '<div><div class="ac-name">' + escapeHtml(u.nickname) + '</div><div class="ac-sub">@' + escapeHtml(u.username) + '</div></div>' +
      '</div>' +
      '<div class="kv-row"><span class="k">角色</span><span class="v" style="font-family:var(--sans)"><span class="badge ' + (u.role === 'admin' ? 'badge-admin' : 'badge-user') + '">' + (u.role === 'admin' ? '管理员' : '普通用户') + '</span></span></div>' +
      '<div class="kv-row"><span class="k">注册时间</span><span class="v" style="font-family:var(--sans)">' + Fmt.fmtTime(u.createdAt) + '</span></div>' +
      '<div class="kv-row"><span class="k">最近登录</span><span class="v" style="font-family:var(--sans)">' + Fmt.fmtTime(u.lastLoginAt) + '</span></div>' +
      '</div>' +
      '<div>' +
      '<div class="card card-pad" style="margin-bottom:16px">' +
      '<div class="card-title">修改昵称</div>' +
      '<div class="field"><label class="field-label">昵称</label><input class="input" id="s-nick" value="' + escapeHtml(u.nickname) + '"><div class="field-error"></div></div>' +
      '<button class="btn btn-primary" id="s-nick-save">保存昵称</button>' +
      '</div>' +
      '<div class="card card-pad">' +
      '<div class="card-title">修改密码</div>' +
      '<div class="field"><label class="field-label">当前密码</label><input class="input" type="password" id="s-old" placeholder="请输入当前密码"><div class="field-error"></div></div>' +
      '<div class="field"><label class="field-label">新密码</label><input class="input" type="password" id="s-new" placeholder="至少 6 位"><div class="field-error"></div></div>' +
      '<div class="field"><label class="field-label">确认新密码</label><input class="input" type="password" id="s-new2" placeholder="再次输入新密码"><div class="field-error"></div></div>' +
      '<button class="btn btn-primary" id="s-pwd-save">修改密码</button>' +
      '</div>' +
      '</div>' +
      '</div>';

    $('#s-nick-save').onclick = function () {
      var input = $('#s-nick');
      var field = input.closest('.field');
      field.classList.remove('has-error');
      var v = input.value.trim();
      if (!v) { field.classList.add('has-error'); field.querySelector('.field-error').textContent = '昵称不能为空'; return; }
      Auth.updateNickname(u.username, v);
      UI.toast('昵称已更新', 'ok');
      renderUserChip();
    };

    $('#s-pwd-save').onclick = function () {
      var oldPwd = $('#s-old').value, newPwd = $('#s-new').value, newPwd2 = $('#s-new2').value;
      [['#s-old', oldPwd], ['#s-new', newPwd]].forEach(function (p) { $(p[0]).closest('.field').classList.remove('has-error'); });
      if (!oldPwd) { $('#s-old').closest('.field').classList.add('has-error'); return; }
      if (newPwd.length < 6) {
        var f = $('#s-new').closest('.field');
        f.classList.add('has-error');
        f.querySelector('.field-error').textContent = '新密码至少 6 位';
        return;
      }
      if (newPwd !== newPwd2) { UI.toast('两次输入的新密码不一致', 'err'); return; }
      var res = Auth.changePassword(u.username, oldPwd, newPwd);
      if (!res.ok) { UI.toast(res.error, 'err'); return; }
      UI.toast('密码已修改，请牢记新密码', 'ok');
      $('#s-old').value = ''; $('#s-new').value = ''; $('#s-new2').value = '';
    };
  };

  /* ---------- 顶栏 / 侧边栏交互 ---------- */
  $('#btn-logout').onclick = function () {
    UI.confirmModal({
      title: '退出登录', body: '确认退出当前账号？本地数据不会丢失。', okText: '退出', danger: true,
      onOk: function () { Auth.logout(); location.replace('index.html'); }
    });
  };
  $('#menu-btn').onclick = function () {
    $('#sidebar').classList.add('open');
    $('#sidebar-mask').classList.add('show');
  };
  $('#sidebar-mask').onclick = closeSidebar;

  /* ---------- 启动 ---------- */
  renderNav();
  render();
})();
