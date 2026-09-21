// 下载授权策略中心前端逻辑
const API_BASE = CONFIG.API_BASE;
let allPolicies = [];
let currentPage = 1;
const PAGE_SIZE = 10;

// 原因码 -> 中文（与后端 REASON_TEXT 对齐，用于页面展示与历史核对）
const REASON_TEXT = {
    no_policy_legacy: '系统尚未配置授权策略，按默认规则放行（不限制）',
    no_matching_policy: '没有适用于该用户与文件类型的授权策略',
    policy_disabled: '匹配的授权策略已停用，不予放行',
    policy_conflict: '存在多条相互重叠的启用策略，判定冲突，不予放行',
    time_outside_window: '当前时间不在策略允许的时间范围内',
    quota_exhausted: '该策略允许的取件次数已用尽',
    invalid_token: '登录令牌缺失或已失效',
    share_invalid: '分享链接已失效',
    share_valid: '分享链接有效',
    matched: '命中策略，允许下载'
};

const SOURCE_TEXT = {
    directory: '文件库目录',
    share_public: '公开分享页',
    share_reentry: '重新进入页面'
};

// ---------------------------------------------------------------- 令牌
const TokenManager = {
    get() { return localStorage.getItem('auth_token'); },
    getUser() { return localStorage.getItem('auth_user'); },
    save(token, user) {
        localStorage.setItem('auth_token', token);
        localStorage.setItem('auth_user', user);
    },
    clear() {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_user');
    },
    headers() { return { 'Authorization': `Bearer ${this.get()}` }; }
};

function showLoading(text = '加载中...') {
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingOverlay').classList.add('active');
}
function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('active');
}
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// ---------------------------------------------------------------- 初始化
document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('authForm').addEventListener('submit', handleLogin);
    if (!TokenManager.get()) {
        showAuthModal();
        return;
    }
    await bootstrap();
});

async function bootstrap() {
    showLoading('加载策略中心...');
    try {
        const resp = await fetch(`${API_BASE}/policies`, { headers: TokenManager.headers() });
        if (resp.status === 401) {
            TokenManager.clear();
            showAuthModal();
            return;
        }
        if (resp.status === 403) {
            document.getElementById('policyList').innerHTML =
                `<div class="empty-msg">当前账号「${escapeHtml(TokenManager.getUser())}」不是策略管理员，无权访问。<br><a href="index.html">返回文件库</a></div>`;
            return;
        }
        allPolicies = await resp.json();
        renderModeBanner();
        renderPolicies();
        loadLogs(1);
    } catch (e) {
        document.getElementById('policyList').innerHTML =
            `<p class="empty-msg">加载失败: ${escapeHtml(e.message)}</p>`;
    } finally {
        hideLoading();
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    showLoading('验证身份...');
    try {
        const resp = await fetch(`${API_BASE}/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const result = await resp.json();
        if (resp.ok && result.success) {
            TokenManager.save(result.token, username);
            document.getElementById('authModal').classList.remove('active');
            await bootstrap();
        } else {
            document.getElementById('authError').textContent = result.error || '登录失败';
        }
    } catch (err) {
        document.getElementById('authError').textContent = `验证失败: ${err.message}`;
    } finally {
        hideLoading();
    }
}

function showAuthModal() {
    document.getElementById('authModal').classList.add('active');
    hideLoading();
}

// ---------------------------------------------------------------- 模式提示
function renderModeBanner() {
    const banner = document.getElementById('modeBanner');
    const enabledCount = allPolicies.filter(p => p.enabled).length;
    if (allPolicies.length === 0) {
        banner.className = 'mode-banner mode-legacy';
        banner.innerHTML = '⚠️ 当前系统<span>没有任何授权策略</span>，下载请求按默认规则全部放行（历史中以“默认放行”标注）。新建策略后立即进入按策略授权模式。';
    } else {
        banner.className = 'mode-banner mode-enforced';
        banner.innerHTML = `🔒 已配置 <span>${allPolicies.length}</span> 条策略（启用 ${enabledCount} 条）。任何不被启用策略完整覆盖、命中停用策略或命中多条冲突策略的请求都将被<span>拒绝</span>。`;
    }
}

// ---------------------------------------------------------------- 策略列表
function renderPolicies() {
    const list = document.getElementById('policyList');
    if (!allPolicies.length) {
        list.innerHTML = '<p class="empty-msg">暂无策略，点击右上角“新建策略”开始配置授权范围。</p>';
        return;
    }
    list.innerHTML = allPolicies.map(p => {
        const users = (p.usernames || []).length ? p.usernames.join('、') : '任意用户';
        const exts = (p.extensions || []).length ? p.extensions.join('、') : '任意类型';
        const time = (p.start_time || p.end_time)
            ? `每日 ${p.start_time || '00:00'} – ${p.end_time || '24:00'}`
            : '全天';
        const limit = p.max_downloads ? `${p.max_downloads} 次/人` : '不限次数';
        return `
        <div class="policy-card ${p.enabled ? '' : 'disabled'}">
            <div class="policy-card-head">
                <span class="policy-name">${escapeHtml(p.name)}</span>
                <span class="policy-state ${p.enabled ? 'on' : 'off'}">${p.enabled ? '● 启用中' : '○ 已停用'}</span>
            </div>
            <p class="policy-desc-text">${escapeHtml(p.description || '')}</p>
            <div class="policy-scope">
                <span class="scope-tag">👤 ${escapeHtml(users)}</span>
                <span class="scope-tag">📎 ${escapeHtml(exts)}</span>
                <span class="scope-tag">🕐 ${escapeHtml(time)}</span>
                <span class="scope-tag">📦 ${escapeHtml(limit)}</span>
            </div>
            <p class="policy-auto-desc">${escapeHtml(p.description_text || '')}</p>
            <div class="policy-card-actions">
                <button class="btn-secondary" onclick="togglePolicy(${p.id})">${p.enabled ? '停用' : '启用'}</button>
                <button class="btn-secondary" onclick="editPolicy(${p.id})">编辑</button>
                <button class="btn-danger" onclick="deletePolicy(${p.id})">删除</button>
            </div>
        </div>`;
    }).join('');
}

// ---------------------------------------------------------------- 新建/编辑
function openPolicyModal() {
    document.getElementById('policyModalTitle').textContent = '新建策略';
    ['policyId', 'policyName', 'policyDesc', 'policyUsers', 'policyExts',
     'policyStart', 'policyEnd', 'policyMax'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('policyErrors').innerHTML = '';
    document.getElementById('policyWarnings').innerHTML = '';
    document.getElementById('policyModal').classList.add('active');
}

function closePolicyModal() {
    document.getElementById('policyModal').classList.remove('active');
}

function editPolicy(id) {
    const p = allPolicies.find(x => x.id === id);
    if (!p) return;
    document.getElementById('policyModalTitle').textContent = '编辑策略';
    document.getElementById('policyId').value = p.id;
    document.getElementById('policyName').value = p.name;
    document.getElementById('policyDesc').value = p.description || '';
    document.getElementById('policyUsers').value = (p.usernames || []).join(', ');
    document.getElementById('policyExts').value = (p.extensions || []).join(', ');
    document.getElementById('policyStart').value = p.start_time || '';
    document.getElementById('policyEnd').value = p.end_time || '';
    document.getElementById('policyMax').value = p.max_downloads ?? '';
    document.getElementById('policyErrors').innerHTML = '';
    document.getElementById('policyWarnings').innerHTML = '';
    document.getElementById('policyModal').classList.add('active');
}

function collectPolicyPayload() {
    return {
        name: document.getElementById('policyName').value,
        description: document.getElementById('policyDesc').value,
        usernames: document.getElementById('policyUsers').value,
        extensions: document.getElementById('policyExts').value,
        start_time: document.getElementById('policyStart').value,
        end_time: document.getElementById('policyEnd').value,
        max_downloads: document.getElementById('policyMax').value
    };
}

async function savePolicy() {
    const id = document.getElementById('policyId').value;
    const payload = collectPolicyPayload();
    const url = id ? `${API_BASE}/policies/${id}` : `${API_BASE}/policies`;
    showLoading(id ? '更新策略...' : '创建策略...');
    try {
        const resp = await fetch(url, {
            method: id ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json', ...TokenManager.headers() },
            body: JSON.stringify(payload)
        });
        const result = await resp.json();
        if (!resp.ok) {
            document.getElementById('policyErrors').innerHTML =
                `<strong>${escapeHtml(result.error || '保存失败')}</strong>` +
                (result.errors || []).map(e => `<div>• ${escapeHtml(e)}</div>`).join('');
            document.getElementById('policyWarnings').innerHTML = '';
            return;
        }
        document.getElementById('policyErrors').innerHTML = '';
        if (result.warnings && result.warnings.length) {
            document.getElementById('policyWarnings').innerHTML =
                result.warnings.map(w => `<div>⚠️ ${escapeHtml(w)}</div>`).join('');
            // 保存成功但有冲突提示：保留弹窗让管理员知晓，刷新后台列表
        } else {
            closePolicyModal();
        }
        await reloadPolicies();
    } catch (e) {
        document.getElementById('policyErrors').innerHTML = `请求失败: ${escapeHtml(e.message)}`;
    } finally {
        hideLoading();
    }
}

async function reloadPolicies() {
    const resp = await fetch(`${API_BASE}/policies`, { headers: TokenManager.headers() });
    if (resp.ok) {
        allPolicies = await resp.json();
        renderModeBanner();
        renderPolicies();
    }
}

async function togglePolicy(id) {
    const p = allPolicies.find(x => x.id === id);
    showLoading(p && p.enabled ? '停用策略...' : '启用策略...');
    try {
        const resp = await fetch(`${API_BASE}/policies/${id}/toggle`, {
            method: 'POST',
            headers: TokenManager.headers()
        });
        const result = await resp.json();
        if (!resp.ok) {
            alert(result.error || '操作失败');
            return;
        }
        await reloadPolicies();
        if (result.warnings && result.warnings.length) {
            alert(result.warnings.join('\n'));
        }
    } catch (e) {
        alert(`操作失败: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function deletePolicy(id) {
    const p = allPolicies.find(x => x.id === id);
    if (!confirm(`确定删除策略「${p ? p.name : id}」吗？删除后原被该策略覆盖的请求将失去授权而被拒绝。`)) return;
    showLoading('删除策略...');
    try {
        const resp = await fetch(`${API_BASE}/policies/${id}`, {
            method: 'DELETE',
            headers: TokenManager.headers()
        });
        const result = await resp.json();
        if (!resp.ok) {
            alert(result.error || '删除失败');
            return;
        }
        await reloadPolicies();
    } catch (e) {
        alert(`删除失败: ${e.message}`);
    } finally {
        hideLoading();
    }
}

// ---------------------------------------------------------------- 预览
async function runPreview() {
    const username = document.getElementById('previewUser').value.trim();
    const filename = document.getElementById('previewFile').value.trim();
    const source = document.getElementById('previewSource').value;
    const box = document.getElementById('previewResult');

    if (!username || !filename) {
        box.innerHTML = '<div class="decision deny">请填写用户名和文件名后再预览。</div>';
        return;
    }
    box.innerHTML = '<div class="decision">正在按当前策略体系判定…</div>';
    try {
        const resp = await fetch(`${API_BASE}/policies/preview`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...TokenManager.headers() },
            body: JSON.stringify({ username, filename, source })
        });
        const result = await resp.json();
        if (!resp.ok) {
            box.innerHTML = `<div class="decision deny"><strong>无法预览：</strong>${
                (result.errors || [result.error || '参数错误']).map(escapeHtml).join('<br>')
            }</div>`;
            return;
        }
        box.innerHTML = renderDecision(result.decision);
    } catch (e) {
        box.innerHTML = `<div class="decision deny">预览请求失败: ${escapeHtml(e.message)}</div>`;
    }
}

function renderDecision(d) {
    const allowed = d.allowed;
    const cls = allowed ? 'allow' : 'deny';
    const icon = allowed ? '✅' : '⛔';
    const title = allowed ? '判定：放行' : '判定：拒绝';
    let quota = '';
    if (allowed && d.limit !== null && d.limit !== undefined) {
        quota = `<div class="decision-row"><span>取件次数</span><b>${d.used ?? 0} / ${d.limit}（剩余 ${d.remaining ?? '-'}）</b></div>`;
    } else if (allowed) {
        quota = `<div class="decision-row"><span>取件次数</span><b>不限</b></div>`;
    }
    const policy = d.policy
        ? `<div class="decision-row"><span>命中策略</span><b>「${escapeHtml(d.policy.name)}」</b></div>`
        : '';
    return `
        <div class="decision ${cls}">
            <div class="decision-title">${icon} ${title}</div>
            <div class="decision-row"><span>请求入口</span><b>${SOURCE_TEXT[d.source] || escapeHtml(d.source)}</b></div>
            <div class="decision-row"><span>原因码</span><code>${escapeHtml(d.reason)}</code></div>
            <div class="decision-row"><span>原因说明</span><span>${escapeHtml(d.reason_text || REASON_TEXT[d.reason] || '')}</span></div>
            ${d.reason_detail ? `<div class="decision-detail">${escapeHtml(d.reason_detail)}</div>` : ''}
            ${policy}
            ${quota}
        </div>`;
}

// ---------------------------------------------------------------- 历史核对
async function loadLogs(page) {
    currentPage = page || 1;
    const params = new URLSearchParams({
        page: currentPage,
        page_size: PAGE_SIZE,
        username: document.getElementById('logUser').value.trim(),
        filename: document.getElementById('logFile').value.trim(),
        decision: document.getElementById('logDecision').value,
        source: document.getElementById('logSource').value
    });
    showLoading('查询判定历史...');
    try {
        const resp = await fetch(`${API_BASE}/policies/decision-logs?${params}`,
            { headers: TokenManager.headers() });
        if (resp.status === 403) {
            document.getElementById('logList').innerHTML =
                '<p class="empty-msg">仅管理员可核对判定历史。</p>';
            return;
        }
        const data = await resp.json();
        renderLogs(data);
    } catch (e) {
        document.getElementById('logList').innerHTML =
            `<p class="empty-msg">查询失败: ${escapeHtml(e.message)}</p>`;
    } finally {
        hideLoading();
    }
}

function renderLogs(data) {
    const list = document.getElementById('logList');
    if (!data.items || !data.items.length) {
        list.innerHTML = '<p class="empty-msg">暂无符合条件的判定记录。</p>';
        document.getElementById('logPager').innerHTML = '';
        return;
    }
    list.innerHTML = `
        <table class="log-table">
            <thead><tr>
                <th>时间</th><th>用户</th><th>文件</th><th>入口</th>
                <th>结论</th><th>原因</th><th>命中策略</th><th>性质</th>
            </tr></thead>
            <tbody>
                ${data.items.map(item => `
                <tr class="log-row ${item.decision}">
                    <td>${escapeHtml(item.created_at)}</td>
                    <td>${escapeHtml(item.username || '-')}</td>
                    <td title="${escapeHtml(item.filename || '')}">${escapeHtml(item.filename || '-')}${item.extension ? '' : ''}</td>
                    <td><span class="source-tag">${SOURCE_TEXT[item.source] || escapeHtml(item.source)}</span></td>
                    <td><span class="log-badge ${item.decision}">${item.decision === 'allow' ? '放行' : '拒绝'}</span></td>
                    <td title="${escapeHtml(item.reason_detail || '')}">
                        ${escapeHtml(item.reason_text || REASON_TEXT[item.reason] || item.reason)}
                    </td>
                    <td>${escapeHtml(item.matched_policy_name || '-')}</td>
                    <td>${item.enforced ? '真实下载' : '页面预判'}</td>
                </tr>`).join('')}
            </tbody>
        </table>`;

    const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
    document.getElementById('logPager').innerHTML = `
        <span class="pager-info">共 ${data.total} 条，第 ${data.page}/${totalPages} 页</span>
        <button class="btn-secondary" ${data.page <= 1 ? 'disabled' : ''} onclick="loadLogs(${data.page - 1})">上一页</button>
        <button class="btn-secondary" ${data.page >= totalPages ? 'disabled' : ''} onclick="loadLogs(${data.page + 1})">下一页</button>`;
}
