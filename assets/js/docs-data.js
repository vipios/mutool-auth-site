/*
 * docs-data.js — 「机制文档」页内容
 * 整理自《MUtool (roothide) 2.2.18 授权机制 — 可提取内容清单》
 */
window.DOCS_HTML = `
<h3>机制概述</h3>
<p>MUtool (roothide) 2.2.18 的授权码机制全部硬编码于 <code class="inline">MUtoolCapture.dylib</code>（fat / arm64e / slice 0）之中，经符号级注解确认（objc_stubs 519 条 selector、__stubs 114 条 C 函数、CFSTR 常量逐一解析）。授权码由设备 UDID 经 HMAC-SHA256 派生，一机一码、可完全离线验证。本页即该机制的完整提取结果，平台中的「授权码生成 / 验证」工具与本页算法 1:1 对应。</p>

<h3>0. 权威基准对拍（已用一手脚本验证）</h3>
<p>本平台的 JS 实现已与逆向工程产出的权威基准 <code class="inline">research/keygen_mutool.py</code> 多向量对拍通过，无任何偏差：</p>
<table class="table">
  <thead><tr><th>用例</th><th>输入（UDID / 待验证码）</th><th>期望 / 实际</th><th>结果</th></tr></thead>
  <tbody>
    <tr><td>生成</td><td class="cell-mono">UDID = 00008020-001A2C3E1E44801E</td><td class="cell-mono">MUZI-MUTOOL-F33A-5853-E382-290E</td><td>一致 ✓</td></tr>
    <tr><td>生成</td><td class="cell-mono">UDID = FFFFFFFF-0000000000000001</td><td class="cell-mono">与基准脚本输出逐一相等</td><td>一致 ✓</td></tr>
    <tr><td>验证（正确码）</td><td class="cell-mono">00008020-… / MUZI-MUTOOL-F33A-5853-E382-290E</td><td class="cell-mono">licensed = true</td><td>通过 ✓</td></tr>
    <tr><td>验证（错误码）</td><td class="cell-mono">00008020-… / MUZI-MUTOOL-0000-0000-0000</td><td class="cell-mono">licensed = false</td><td>拒绝 ✓（符合预期）</td></tr>
  </tbody>
</table>
<p class="small">最后一行是<strong>负向用例</strong>：用正确的 UDID 去验一个错误的授权码，验证器理应判失败——这恰恰证明验证逻辑不会误放行，它"被拒绝（licensed=false）"而非"测试失败"。对拍基准：<code class="inline">python keygen_mutool.py &lt;UDID&gt;</code> 与 <code class="inline">python keygen_mutool.py --verify &lt;UDID&gt; &lt;code&gt;</code>。算法常量（SECRET_KEY 取自 CFSTR@0x35570、BUNDLE_ID=com.muzi.mutool、前缀 MUZI-MUTOOL-）与本平台完全一致。</p>

<h3>1. 算法常量（全部硬编码于二进制）</h3>
<table class="table">
  <thead><tr><th>项</th><th>值</th><th>出处</th></tr></thead>
  <tbody>
    <tr><td>HMAC 密钥</td><td class="cell-mono">MuziSource-Auth-2026-v1-Secret-Key</td><td>（34 字节）CFSTR@0x35570</td></tr>
    <tr><td>HMAC 数据</td><td class="cell-mono">com.muzi.mutool|&lt;UDID&gt;</td><td><code class="inline">stringWithFormat:@"%@|%@"</code></td></tr>
    <tr><td>算法</td><td class="cell-mono">HMAC-SHA256</td><td><code class="inline">CCHmac(kCCHmacAlgSHA256)</code>，stub <code class="inline">_CCHmac</code>@0x211a4，生成器 0x9790</td></tr>
    <tr><td>编码</td><td class="cell-mono">32 字节 MAC → "%02X" 大写十六进制（64 字符）</td><td>0x97c0 循环</td></tr>
    <tr><td>截取</td><td class="cell-mono">hex 前 16 字符（substringToIndex:16）</td><td>0x97ec</td></tr>
    <tr><td>分组</td><td class="cell-mono">前 16 字符按 4 字分组、"-" 连接 → AAAA-BBBB-CCCC-DDDD</td><td>0x9820 循环</td></tr>
    <tr><td>最终格式</td><td class="cell-mono">MUZI-MUTOOL-AAAA-BBBB-CCCC-DDDD</td><td><code class="inline">stringWithFormat:@"MUZI-%@-%@"</code>，CFSTR@0x354f0/0x35510</td></tr>
  </tbody>
</table>

<h3>2. 授权码生成流程</h3>
<pre><span class="c"># 以 UDID 00008020-001A2C3E1E44801E 为例（与平台生成器输出一致）</span>
data    = <span class="s">"com.muzi.mutool|00008020-001A2C3E1E44801E"</span>
mac     = HMAC-SHA256(<span class="s">"MuziSource-Auth-2026-v1-Secret-Key"</span>, data)
hex     = <span class="s">"F33A5853E382290EB8427EE16D79D1B26E52CBD7B3BF59959FAAC5AD21399F5D"</span>
body16  = hex[0:16]                    <span class="c"># F33A5853E382290E</span>
grouped = body16[0:4] + "-" + body16[4:8] + "-" + body16[8:12] + "-" + body16[12:16]
code    = <span class="s">"MUZI-MUTOOL-F33A-5853-E382-290E"</span></pre>

<h3>3. UDID 获取链（0x9598）</h3>
<pre>dlopen(<span class="s">"/usr/lib/libMobileGestalt.dylib"</span>, RTLD_NOW)
  → dlsym(<span class="s">"MGCopyAnswer"</span>)
  → MGCopyAnswer(@"UniqueDeviceID")            <span class="c"># CFSTR@0x355b0</span>
回退 1: CFPreferencesCopyAppValue(@"MUToolUDID", @"com.muzi.mutoolprefs")
回退 2: @""（空串 → HMAC data = "com.muzi.mutool|"）
结果缓存到全局 @0x3c448；dlopen/dlsym 方式避免静态链接 MobileGestalt（防 nm 直接看到符号）</pre>
<p class="small">桩映射交叉引用：<code class="inline">MGCopyAnswer</code> 经由 <code class="inline">dlopen("/usr/lib/libMobileGestalt.dylib")</code> + <code class="inline">dlsym</code> 动态解析（非静态链接，规避 nm 直接暴露符号）；授权码读取经桩 <code class="inline">_CFPreferencesCopyAppValue@0x211f8</code>；生成器 HMAC 经桩 <code class="inline">_CCHmac@0x211a4</code>。完整映射见随项目提供的 <code class="inline">stubmap.json / ostubmap.json</code>。</p>

<h3>4. 授权码存储位置（验证器 0x7860）</h3>
<pre>① jbroot("/var/mobile/Library/Preferences/com.muzi.mutoolprefs.plist")["licenseCode"]   <span class="c"># 文件优先</span>
② CFPreferencesCopyAppValue("licenseCode", "com.muzi.mutoolprefs")                     <span class="c"># cfprefsd 兜底</span></pre>

<h3>5. 比对规则（0x9414）</h3>
<pre>norm(s) = [s stringByReplacingOccurrencesOfString:@"-" withString:@""].uppercaseString;
licensed = [norm(stored) isEqualToString:norm(expected)];</pre>
<ul>
  <li><b>大小写不敏感、短横线不敏感</b>：<code class="inline">muzi-mutool-f33a5853e382290e</code> 与 <code class="inline">MUZI-MUTOOL-F33A-5853-E382-290E</code> 等价。</li>
  <li><b>一机一码</b>：换设备（UDID 变）即失效，但码可离线重算。</li>
</ul>

<h3>6. 已知绕过路径（反汇编证实）</h3>
<table class="table">
  <thead><tr><th>路径</th><th>位置</th><th>说明</th></tr></thead>
  <tbody>
    <tr><td>cfprefsd 信任兜底</td><td class="cell-mono">0x7a34</td><td>UDID 取不到时，prefs 里 <code class="inline">licenseCode</code> 非空即判已授权（日志 <code class="inline">auth trust cfprefsd code (udid unavailable)</code>）</td></tr>
    <tr><td>离线重算</td><td class="cell-mono">—</td><td>密钥在本地，输入 UDID 即可产出合法码（即本平台「授权码生成」所复刻的逻辑）</td></tr>
    <tr><td>Patch</td><td class="cell-mono">—</td><td>全局授权标志 @0x3c619，改一处字节即可永久置 1</td></tr>
  </tbody>
</table>
<div class="callout warn">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
  <div><b>安全评估：</b>该机制的安全性完全依赖于密钥的保密性。由于密钥硬编码在客户端二进制中，任何拿到 dylib 的人都可以离线重算任意设备的授权码；加之 cfprefsd 信任兜底与单字节 Patch 路径，它只能 deter 普通用户，无法抵御有针对性的破解。若需提升强度，应将校验移至服务端，并对 UDID 做防伪造绑定。</div>
</div>

<h3>7. 反汇编证据索引（MUtoolCapture.dylib, arm64e）</h3>
<table class="table">
  <thead><tr><th>功能</th><th>地址</th></tr></thead>
  <tbody>
    <tr><td>授权码生成器</td><td class="cell-mono">0x96e8 – 0x98e8</td></tr>
    <tr><td>UDID 获取（MGCopyAnswer）</td><td class="cell-mono">0x9598 – 0x9684</td></tr>
    <tr><td>比对函数（归一化 + isEqualToString）</td><td class="cell-mono">0x9414 – 0x9598</td></tr>
    <tr><td>主验证器（plist / cfprefsd / 兜底）</td><td class="cell-mono">0x7860 – 0x7b28</td></tr>
    <tr><td>授权全局标志 / UDID 缓存</td><td class="cell-mono">0x3c619（字节）/ 0x3c448</td></tr>
  </tbody>
</table>

<h3>8. 与本平台的对应关系</h3>
<p>「授权码生成」页完整执行第 1、2 节的流水线（可调 Bundle ID / 产品代号 / 前缀 / 数据段长度，默认值即原版参数）；「授权码验证」页执行第 5 节的归一化比对（并按长度自适应，见第 9 节）；第 6 节的绕过路径在本平台上以<b>安全提示</b>形式呈现，不提供任何二进制 Patch 能力。</p>

<h3>9. 长度自定义（平台扩展）</h3>
<p>「授权码生成」页标签栏右侧的齿轮入口提供<b>数据段长度自定义</b>：数据段可取 HMAC-SHA256 大写十六进制输出（64 字符）的前 4–64 位中任意长度，按 4 字分组（原版固定 16 位 / 4 组）。设置持久化保存，对单个与批量生成即时生效。</p>
<ul>
  <li><b>生成</b>：流水线展示与结果区会同步显示当前长度（截取前 N 字符 → 分 N/4 组），非默认长度会标注「原版客户端不识别」。</li>
  <li><b>验证（长度自适应）</b>：验证时按授权码<b>自身的数据段长度</b>计算期望值——例如用 12 位生成的码，验证器按 12 位截取期望值比对；用 24 位生成的码则按 24 位比对。因此任意长度生成的码都能被正确判定，无需手动切换长度设置，这与第 5 节「归一化后整体比对」的语义一致。</li>
  <li><b>兼容性提醒</b>：原版 MUtool 客户端固定只认 16 位（4 组）格式；自定义长度生成的授权码<b>仅在本平台内自洽</b>，不能用于真实客户端激活。</li>
</ul>

<h3>10. 随项目提供的研究基准（research/）</h3>
<p>为便于离线复现与持续对拍，以下一手逆向工具链已随本项目提供于 <code class="inline">research/</code> 目录，均在逆向分析的同一 binary 上产出：</p>
<table class="table">
  <thead><tr><th>文件</th><th>用途</th></tr></thead>
  <tbody>
    <tr><td class="cell-mono">keygen_mutool.py</td><td>授权码生成 / 验证权威基准（HMAC-SHA256 1:1 还原，含 --verify）</td></tr>
    <tr><td class="cell-mono">disasm_auth.py</td><td>反汇编授权函数（生成器 0x9684、验证器 0x7860）</td></tr>
    <tr><td class="cell-mono">annotate_auth.py</td><td>符号级注解：objc_stubs → selector、CFSTR 常量解析</td></tr>
    <tr><td class="cell-mono">resolve_stubs.py</td><td>解析 __stubs → 导入符号（arm64e chained fixups）</td></tr>
    <tr><td class="cell-mono">stubmap.json / ostubmap.json</td><td>C 函数桩 / Objective-C selector 桩映射表</td></tr>
    <tr><td class="cell-mono">macho.py</td><td>Mach-O 解析基础库</td></tr>
  </tbody>
</table>
<div class="callout info">说明：完整的《MUtool 逆向分析报告》HTML 未纳入本公开站点——其第 3、4 节涉及 setuid-root 提权模型与私有 entitlement 仿冒等与安全规避强相关、且超出"授权码机制"范畴的内容，仅作本地研究存档，不在可分享页面中呈现。本页仅聚焦并已 1:1 复刻第 5 节授权验证机制。</div>
`;
