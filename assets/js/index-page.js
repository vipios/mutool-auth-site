/*
 * index-page.js — 登录 / 注册门户逻辑
 */
(function () {
  'use strict';
  var $ = UI.$, escapeHtml = UI.escapeHtml;

  var box = $('#auth-box');
  var mode = 'login'; // login | register

  function fieldError(input, msg) {
    var field = input.closest('.field');
    field.classList.add('has-error');
    var err = field.querySelector('.field-error');
    if (err) err.textContent = msg;
  }

  function clearErrors(root) {
    UI.$$('.field', root).forEach(function (f) { f.classList.remove('has-error'); });
  }

  function render() {
    var user = Auth.current();
    if (user) {
      box.innerHTML =
        '<div class="auth-welcome">' +
        '<div class="w-icon">' + UI.ICONS.check + '</div>' +
        '<h2>欢迎回来，' + escapeHtml(user.nickname) + '</h2>' +
        '<p>你已登录（' + escapeHtml(user.username) + (user.role === 'admin' ? ' · 管理员' : '') + '），可直接进入授权管理控制台。</p>' +
        '<button class="btn btn-primary btn-block" id="btn-enter">进入控制台</button>' +
        '<div style="margin-top:14px"><button class="btn-link" id="btn-logout">退出登录</button></div>' +
        '</div>';
      $('#btn-enter').onclick = function () { location.href = 'app.html'; };
      $('#btn-logout').onclick = function () {
        Auth.logout();
        UI.toast('已退出登录', 'info');
        render();
      };
      return;
    }

    var isLogin = mode === 'login';
    box.innerHTML =
      '<div class="auth-tabs">' +
      '<button class="' + (isLogin ? 'active' : '') + '" data-mode="login">登录</button>' +
      '<button class="' + (!isLogin ? 'active' : '') + '" data-mode="register">注册</button>' +
      '</div>' +
      '<h2>' + (isLogin ? '登录控制台' : '注册新账号') + '</h2>' +
      '<p class="auth-desc">' + (isLogin ? '使用平台账号登录，管理授权码与授权记录。' : '注册后默认成为普通用户，管理员可在后台调整角色。') + '</p>' +
      '<form id="auth-form" novalidate>' +
      '<div class="field"><label class="field-label">用户名<span class="req">*</span></label>' +
      '<input class="input" id="f-username" placeholder="请输入用户名" autocomplete="username">' +
      '<div class="field-error"></div></div>' +
      (isLogin ? '' :
        '<div class="field"><label class="field-label">昵称</label>' +
        '<input class="input" id="f-nickname" placeholder="选填，默认为用户名">' +
        '<div class="field-error"></div></div>') +
      '<div class="field"><label class="field-label">密码<span class="req">*</span></label>' +
      '<input class="input" type="password" id="f-password" placeholder="' + (isLogin ? '请输入密码' : '至少 6 位字符') + '" autocomplete="' + (isLogin ? 'current-password' : 'new-password') + '">' +
      '<div class="field-error"></div></div>' +
      (isLogin ? '' :
        '<div class="field"><label class="field-label">确认密码<span class="req">*</span></label>' +
        '<input class="input" type="password" id="f-password2" placeholder="再次输入密码" autocomplete="new-password">' +
        '<div class="field-error"></div></div>') +
      '<button class="btn btn-primary btn-block" type="submit" style="margin-top:4px">' + (isLogin ? '登 录' : '注 册') + '</button>' +
      '</form>' +
      (isLogin ?
        '<div class="auth-demo">演示管理员账号：<code>admin</code> / <code>Admin@123</code><br>演示普通账号：<code>tester</code> / <code>test123456</code></div>' :
        '<div class="auth-demo">注册即表示同意：本演示平台数据仅存储于当前浏览器 localStorage，请勿存放真实敏感信息。</div>');

    UI.$$('.auth-tabs button', box).forEach(function (btn) {
      btn.onclick = function () { mode = btn.dataset.mode; render(); };
    });

    var form = $('#auth-form');
    form.onsubmit = function (e) {
      e.preventDefault();
      clearErrors(box);
      var username = $('#f-username').value;
      var password = $('#f-password').value;

      if (!username.trim()) return fieldError($('#f-username'), '请输入用户名');
      if (!password) return fieldError($('#f-password'), '请输入密码');

      var res;
      if (isLogin) {
        res = Auth.login(username, password);
        if (!res.ok) {
          UI.toast(res.error, 'err');
          return fieldError(password ? $('#f-password') : $('#f-password'), res.error);
        }
        UI.toast('登录成功，正在进入控制台…', 'ok');
        setTimeout(function () { location.href = 'app.html'; }, 350);
      } else {
        var nickname = $('#f-nickname').value;
        var password2 = $('#f-password2').value;
        if (!/^[a-zA-Z0-9_]{3,20}$/.test(username.trim())) return fieldError($('#f-username'), '用户名需为 3-20 位字母、数字或下划线');
        if (password.length < 6) return fieldError($('#f-password'), '密码至少 6 位');
        if (password !== password2) return fieldError($('#f-password2'), '两次输入的密码不一致');
        res = Auth.register(username, nickname, password);
        if (!res.ok) {
          UI.toast(res.error, 'err');
          return fieldError($('#f-username'), res.error);
        }
        UI.toast('注册成功，正在进入控制台…', 'ok');
        setTimeout(function () { location.href = 'app.html'; }, 350);
      }
    };
  }

  render();
})();
