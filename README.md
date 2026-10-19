# MUtool 授权管理平台

基于 MUtool (roothide) 2.2.18 授权机制逆向分析复刻的**授权码生成 / 验证 + 在线管理后台**（纯静态站点，零外部依赖）。

## 一键访问

| 入口 | 地址 |
|---|---|
| 源码仓库 | https://github.com/vipios/mutool-auth-site |
| 在线站点（GitHub Pages 主） | https://vipios.github.io/mutool-auth-site/ |
| 镜像加速 | 见下方说明 |

> **镜像说明**：`gh-proxy.com` 等公共代理通常只反代 `github.com` / `raw.githubusercontent.com`，**不反代 `*.github.io` 站点**，直接用其代理本站点会返回 404。如需国内加速访问，推荐把本仓库一键部署到 **Cloudflare Pages / Vercel / Netlify**（原生支持静态站、对接本仓库即部署，国内可达性优于 GitHub Pages），或自建反代。

## 登录账号

| 角色 | 用户名 | 密码 |
|---|---|---|
| 管理员 | `admin` | `xx160801` |
| 普通用户 | `tester` | `test123456` |

- 首次打开自动种子演示数据（演示记录、图表）。
- 管理员可在「用户管理」里新建 / 改密码 / 删除用户、切换角色。
- 注册新账号默认普通用户。

## 功能

- **授权码生成**：输入 UDID，按原版算法离线派生授权码（单个 / 批量），展示 5 步流水线。
- **授权码验证**：归一化比对（大小写、短横线不敏感）。
- **授权记录**：生成 / 验证审计日志，支持搜索、CSV 导出、删除、清空。
- **用户管理**：仅管理员可见。
- **机制文档**：逆向分析完整 Web 版（算法常量、UDID 链、绕过路径、地址索引）。
- **研究基准**（`research/`）：一手逆向工具链（keygen_mutool.py 等），与站点算法 1:1 对拍。

## 算法（1:1 复刻）

```
授权码 = "MUZI-MUTOOL-" + HMAC-SHA256(
            key  = "MuziSource-Auth-2026-v1-Secret-Key",
            data = "com.muzi.mutool|<UDID>"
          ) 大写十六进制前 16 字符，按 4 字分组 → AAAA-BBBB-CCCC-DDDD
```

对拍向量：UDID `00008020-001A2C3E1E44801E` → `MUZI-MUTOOL-F33A-5853-E382-290E`。

## 部署

本站为纯静态站点，由 **GitHub Pages** 从 `main` 分支根目录托管（legacy 部署）。
推送新提交到 `main` 即自动重新发布。

## 免责声明

本项目为授权机制的**逆向研究与复刻演示**，仅供合法授权持有者、安全研究人员参考。
密钥硬编码于前端二进制、本站点复刻同样暴露于客户端，请勿用于规避正版授权或任何违法用途。
