## How to Run

### Docker 启动（推荐）

```bash
# 构建并启动所有服务
docker-compose up --build -d

# 查看运行状态
docker-compose ps

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

启动后访问：
- 前端：http://localhost:8081
- 后端API：http://localhost:8636

### 本地启动

**后端：**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

**前端：**
直接用浏览器打开 `frontend/index.html`，或使用任意静态服务器：
```bash
cd frontend
python -m http.server 8081
```

## Services

| 服务 | 端口 | 说明 |
|------|------|------|
| frontend | 8081 | Nginx静态文件服务 + API代理 |
| backend | 8636 | Flask API服务 |

## 测试账号

| 用户名 | 密码 |
|--------|------|
| admin | admin123 |
| user | user123 |
| test | test123 |

## 运行测试

```bash
cd backend
pip install -r requirements.txt
pytest -v
```

## 题目内容

做一个下载网站，要求：
- 有加载动画
- 有上传按钮
- 点击下载时进行身份验证
- 验证完成后自动跳转下载
- 使用Python后端
- 前端端口：8081
- 后端端口：8636
- 支持Docker部署（ARM和X86跨平台）

---

## 项目介绍

做一个下载网站要有加载动画和上传按钮并且点击下载的时候会有身份验证的网页完成后自动跳转要用Python制作完成后放在文件夹中并且搭建服务器

### 功能特性

- 📤 文件上传
- 📥 文件下载（需身份验证）
- 🔐 用户身份验证
- ⏳ 加载动画效果
- 🐳 Docker一键部署
- 🛡️ 下载授权策略中心（按用户 / 文件类型 / 时间范围 / 取件次数组合授权）

### 下载授权策略中心

管理员（默认 `admin`，可用环境变量 `ADMIN_USERNAMES` 配置多个）登录后，
首页会出现 **🛡️ 下载授权策略中心** 入口（`policy.html`）。

**策略范围（四个维度可任意组合，但至少限定一项）**

| 维度 | 含义 | 留空时 |
|------|------|--------|
| 用户 | 逗号分隔的用户名，如 `user,test` | 任意已登录用户 |
| 文件类型 | 扩展名，如 `pdf,zip,docx` | 任意类型 |
| 时间范围 | 每日允许时段 `HH:MM–HH:MM`，支持跨午夜（如 `22:00–06:00`） | 全天 |
| 取件次数 | 每人在该策略下的下载次数上限 | 不限 |

**判定规则（默认拒绝，绝不误放行）**

- 系统中**一条策略都没有**时，沿用默认放行（历史标注 `no_policy_legacy`），保证已有合法请求不被误伤；新建第一条策略后立即进入“按策略授权”模式。
- **空规则**：用户/类型/时间一项都不限定的策略在保存时即被拒绝，防止形成无条件放行。
- **重叠规则**：保存时给出冲突提示；请求同时命中多条启用策略时判 `policy_conflict` 拒绝，并列明冲突策略。
- **策略停用**：仅被停用策略覆盖的请求判 `policy_disabled` 拒绝（停用不会变成放行）。
- **无匹配策略 / 不在时间窗 / 次数用尽**：分别判 `no_matching_policy`、`time_outside_window`、`quota_exhausted` 拒绝，并给出具体原因。
- **失效令牌**：在进入策略判定前判 `invalid_token` 拒绝并要求重新登录。

**三个入口判定一致**：文件库目录（`/api/download`）、公开分享页（`/api/share/<id>/download`）、
重新进入的分享页（`/api/share/<id>` 的预判）全部复用同一个授权判定引擎
（`policies.evaluate_download`）。登录用户在分享入口同样受策略约束且不重复累加分享链接计数；
无令牌的访客仍按分享链接自身的有效期/次数规则下载。

**策略中心页面提供**

- 策略增删改、一键启停、人类可读的策略说明
- 保存/启停时的重叠冲突提示
- 命中结果预览（dry-run，不消耗取件次数、不影响正式判定）
- 授权判定历史核对（按用户/文件/结论/入口过滤、分页，区分“真实下载”与“页面预判”）

| 拒绝原因码 | 含义 |
|-----------|------|
| `invalid_token` | 令牌缺失或已失效 |
| `no_matching_policy` | 没有策略覆盖该用户 × 文件类型 |
| `policy_disabled` | 唯一匹配的策略已停用 |
| `policy_conflict` | 多条启用策略同时命中 |
| `time_outside_window` | 当前不在允许时段 |
| `quota_exhausted` | 取件次数已用尽 |

### 文件上传安全策略

项目采用扩展名黑名单机制，禁止上传以下类型的文件：

`exe, sh, bat, cmd, ps1, py, php, jsp, cgi, pl`

为什么用黑名单而不是白名单？
- 白名单需要预先列出所有允许的格式，每次有新格式都要手动添加，维护成本高
- 作为下载站，用户上传的文件类型多样且不可预测，白名单容易漏掉合法格式
- 黑名单只需拦截少量危险的可执行文件类型（如脚本、二进制程序），防止服务器被上传恶意代码利用
- 配合文件大小限制（默认50MB），已经能满足基本的安全需求

### 技术栈

- 前端：HTML + CSS + JavaScript
- 后端：Python Flask
- 部署：Docker + Nginx
