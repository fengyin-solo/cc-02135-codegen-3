// 下载授权策略中心
const API_BASE = CONFIG.API_BASE;

let meta = { users: [], common_types: [], existing_file_types: [], server_time: Date.now() / 1000 };
let policies = [];
let editorUsers = new Set();
let editorTypes = new Set();
let lastValidPreviewPayload = null;

// ---------------------------------------------------------------------------
// Token 管理（与 app.js 一致，localStorage 共享）
// ---------------------------------------------------------------------------
const TokenManager = {
    TOKEN_KEY: 'auth_token',
    USER_KEY: 'auth_user',
    get() { return localStorage.getItem(this.TOKEN_KEY); },
    getUser() { return localStorage.getItem(this.USER_KEY); },
    clear() {
        localStorage.removeItem(this.TOKEN_KEY);
        localStorage.removeItem(this.USER_KEY);
    },
    async isValid() {
        const token = this.get();
        if (!token) return false;
        try {
            const r = await fetch(`${API_BASE}/refresh-token?token=${token}`, { method: 'POST' });
            return r.ok;
        } catch { return false; }
    }
};

function authHeaders() {
    return { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TokenManager.get()}` };
}

function showLoading(text = '加载中...') {
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingOverlay').classList.add('active');
}
function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('active');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text == null ? '' : String(text);
    return div.innerHTML;
}

function logout() {
    TokenManager.clear();
    location.reload();
}

// ---------------------------------------------------------------------------
// 时间工具
// ---------------------------------------------------------------------------
function toLocalInputValue(epoch) {
    if (!epoch) return '';
    const d = new Date(epoch * 1000);
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function inputValueToEpoch(value) {
    if (!value) return null;
    const t = new Date(value).getTime();
    return Number.isNaN(t) ? null : t / 1000;
}
function formatTs(epoch) {
    if (!epoch) return '长期';
    return new Date(epoch * 1000).toLocaleString('zh-CN', { hour12: false });
}

// ---------------------------------------------------------------------------
// 页面初始化
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
    if (!(await TokenManager.isValid())) {
        TokenManager.clear();
        document.getElementById('userBar').classList.add('hidden');
        document.getElementById('loginNeeded').classList.remove('hidden');
        document.getElementById('newPolicyBtn').disabled = true;
        return;
    }
    const user = TokenManager.getUser();
    document.getElementById('currentUser').textContent = user;
    document.getElementById('userAvatar').textContent = user.charAt(0).toUpperCase();
    document.getElementById('userBar').classList.remove('hidden');

    bindEditorEvents();
    await loadMeta();
    await loadPolicies();
    await loadHistory();
});

async function loadMeta() {
    try {
        const r = await fetch(`${API_BASE}/policies/meta`, { headers: { Authorization: `Bearer ${TokenManager.get()}` } });
        if (r.ok) meta = await r.json();
    } catch (e) { /* 忽略，使用内置候选 */ }
}

function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    document.getElementById('policiesTab').classList.toggle('hidden-wide', tab !== 'policies');
    document.getElementById('historyTab').classList.toggle('hidden-wide', tab !== 'history');
    if (tab === 'history') loadHistory();
}

// ---------------------------------------------------------------------------
// 策略列表
// ---------------------------------------------------------------------------
async function loadPolicies() {
    showLoading('加载策略...');
    try {
        const r = await fetch(`${API_BASE}/policies`, { headers: { Authorization: `Bearer ${TokenManager.get()}` } });
        if (r.status === 401) { TokenManager.clear(); location.reload(); return; }
        const data = await r.json();
        policies = data.policies || [];
        renderCenterState(data);
        renderPolicyList();
    } catch (e) {
        document.getElementById('policyList').innerHTML = `<p class="empty-msg">加载失败: ${escapeHtml(e.message)}</p>`;
    } finally {
        hideLoading();
    }
}

function renderCenterState(data) {
    const banner = document.getElementById('centerState');
    if (!data.enforced) {
        banner.className = 'policy-banner warn';
        banner.innerHTML = '⚠️ 策略中心当前<strong>没有启用中的策略</strong>。'
            + '尚未配置任何策略时，下载沿用原有的登录/分享校验（兼容放行）；'
            + '<strong>一旦创建过策略，全部停用将导致所有下载被拒绝并向用户说明原因</strong>。';
    } else {
        banner.className = 'policy-banner ok';
        banner.innerHTML = `✅ 策略中心运行中：<strong>${data.active_count}</strong> 条启用策略，所有下载请求均按策略判定（目录页、公开分享页、重新进入页面结果一致）。`;
    }
}

function scopeText(list, allLabel) {
    if (list.includes('*')) return `<span class="scope-all">${allLabel}</span>`;
    return list.map(x => `<span class="scope-tag">${escapeHtml(x)}</span>`).join('');
}

function stateBadge(p) {
    const map = {
        active: ['valid', '启用中'],
        pending: ['pending', '未到生效时间'],
        expired: ['invalid', '已过结束时间'],
        disabled: ['invalid', '已停用'],
    };
    const [cls, text] = map[p.enabled ? p.time_state : 'disabled'];
    return `<span class="share-item-status ${cls}">${text}</span>`;
}

function renderPolicyList() {
    const list = document.getElementById('policyList');
    if (!policies.length) {
        list.innerHTML = '<p class="empty-msg">暂无策略。新建一条策略后，所有下载将严格按授权范围判定。</p>';
        return;
    }
    list.innerHTML = policies.map(p => {
        const quota = p.max_downloads == null
            ? '不限次数'
            : `${p.used_downloads} / ${p.max_downloads} 次（剩余 ${p.remaining_downloads}）`;
        const conflictsHtml = (p.conflicts || []).map(c => `
            <div class="conflict-item">⛔ ${escapeHtml(c.message)}（重叠维度：${c.dimensions.map(escapeHtml).join('、')}）</div>
        `).join('');
        return `
        <div class="policy-card ${p.enabled ? '' : 'disabled-card'}">
            <div class="policy-card-head">
                <div>
                    <span class="policy-name">${escapeHtml(p.name)}</span>
                    ${stateBadge(p)}
                </div>
                <div class="policy-card-actions">
                    <button class="mini-btn" onclick="quickPreview('${p.id}')">结果预览</button>
                    <button class="mini-btn" onclick="openEditor('${p.id}')">编辑</button>
                    <button class="mini-btn" onclick="togglePolicy('${p.id}', ${!p.enabled})">${p.enabled ? '停用' : '启用'}</button>
                    <button class="mini-btn danger" onclick="resetUsage('${p.id}')">清零计数</button>
                    <button class="mini-btn danger" onclick="removePolicy('${p.id}')">删除</button>
                </div>
            </div>
            <p class="policy-desc">${escapeHtml(p.description)}</p>
            ${conflictsHtml ? `<div class="conflict-box">${conflictsHtml}</div>` : ''}
            <div class="policy-scope-grid">
                <div><span class="scope-label">用户</span><div>${scopeText(p.users, '所有用户')}</div></div>
                <div><span class="scope-label">文件类型</span><div>${scopeText(p.file_types.map(t => '.' + t), '所有类型')}</div></div>
                <div><span class="scope-label">时间范围</span><div>${formatTs(p.start_at)} ~ ${formatTs(p.end_at)}</div></div>
                <div><span class="scope-label">取件次数</span><div>${quota}</div></div>
            </div>
        </div>`;
    }).join('');
}

// ---------------------------------------------------------------------------
// 编辑器
// ---------------------------------------------------------------------------
function renderChips(containerId, values, selectedSet, allowWildcard, wildcardLabel) {
    const box = document.getElementById(containerId);
    const all = allowWildcard ? ['*', ...values.filter(v => v !== '*')] : values;
    box.innerHTML = all.map(v => {
        const label = v === '*' ? wildcardLabel : v;
        return `<label class="chip ${selectedSet.has(v) ? 'selected' : ''}">
            <input type="checkbox" value="${escapeHtml(v)}" ${selectedSet.has(v) ? 'checked' : ''}>
            ${escapeHtml(label)}
        </label>`;
    }).join('');
    box.querySelectorAll('input').forEach(input => {
        input.addEventListener('change', () => {
            if (input.checked) selectedSet.add(input.value); else selectedSet.delete(input.value);
            liveValidate();
            updateAutoDescription();
        });
    });
}

function bindEditorEvents() {
    document.getElementById('customUser').addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const v = e.target.value.trim();
            if (v) { editorUsers.add(v); e.target.value = ''; refreshUserChips(); }
        }
    });
    document.getElementById('customType').addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const v = e.target.value.trim().replace(/^\./, '').toLowerCase();
            if (v) { editorTypes.add(v); e.target.value = ''; refreshTypeChips(); }
        }
    });
    ['policyName', 'policyStart', 'policyEnd', 'policyMaxDownloads'].forEach(id => {
        document.getElementById(id).addEventListener('input', () => { liveValidate(); updateAutoDescription(); });
    });
    document.getElementById('policyUnlimited').addEventListener('change', e => {
        const input = document.getElementById('policyMaxDownloads');
        input.disabled = e.target.checked;
        if (e.target.checked) input.value = -1; else input.value = 10;
        liveValidate();
        updateAutoDescription();
    });
}

function refreshUserChips() {
    const merged = Array.from(new Set([...(meta.users || []), ...editorUsers]));
    renderChips('userChips', merged, editorUsers, true, '所有用户（*）');
    liveValidate();
    updateAutoDescription();
}
function refreshTypeChips() {
    const merged = Array.from(new Set([...(meta.common_types || []), ...(meta.existing_file_types || []), ...editorTypes]));
    renderChips('typeChips', merged, editorTypes, true, '所有类型（*）');
    liveValidate();
    updateAutoDescription();
}

function openEditor(id) {
    document.getElementById('policyValidation').innerHTML = '';
    document.getElementById('autoDescription').textContent = '';
    if (id) {
        const p = policies.find(x => x.id === id);
        if (!p) return;
        document.getElementById('editorTitle').textContent = '编辑授权策略';
        document.getElementById('policyId').value = p.id;
        document.getElementById('policyName').value = p.name;
        document.getElementById('policyDescription').value = '';
        editorUsers = new Set(p.users);
        editorTypes = new Set(p.file_types);
        document.getElementById('policyStart').value = toLocalInputValue(p.start_at);
        document.getElementById('policyEnd').value = toLocalInputValue(p.end_at);
        document.getElementById('policyUnlimited').checked = p.max_downloads == null;
        document.getElementById('policyMaxDownloads').value = p.max_downloads == null ? -1 : p.max_downloads;
        document.getElementById('policyMaxDownloads').disabled = p.max_downloads == null;
        document.getElementById('policyEnabled').checked = p.enabled;
    } else {
        document.getElementById('editorTitle').textContent = '新建授权策略';
        document.getElementById('policyId').value = '';
        document.getElementById('policyName').value = '';
        document.getElementById('policyDescription').value = '';
        editorUsers = new Set((meta.users || []).slice(0, 1));
        editorTypes = new Set((meta.existing_file_types || meta.common_types || []).slice(0, 1));
        document.getElementById('policyStart').value = '';
        document.getElementById('policyEnd').value = '';
        document.getElementById('policyUnlimited').checked = false;
        document.getElementById('policyMaxDownloads').disabled = false;
        document.getElementById('policyMaxDownloads').value = 10;
        document.getElementById('policyEnabled').checked = true;
        document.getElementById('customUser').value = '';
        document.getElementById('customType').value = '';
    }
    refreshUserChips();
    refreshTypeChips();
    document.getElementById('policyModal').classList.add('active');
}
function closeEditor() {
    document.getElementById('policyModal').classList.remove('active');
}

function collectPayload() {
    return {
        name: document.getElementById('policyName').value.trim(),
        description: document.getElementById('policyDescription').value.trim() || null,
        users: Array.from(editorUsers),
        file_types: Array.from(editorTypes),
        start_at: inputValueToEpoch(document.getElementById('policyStart').value),
        end_at: inputValueToEpoch(document.getElementById('policyEnd').value),
        max_downloads: document.getElementById('policyUnlimited').checked
            ? -1 : parseInt(document.getElementById('policyMaxDownloads').value, 10),
        enabled: document.getElementById('policyEnabled').checked,
    };
}

// 实时校验：空规则 / 非法时间 / 次数为 0
function liveValidate() {
    const box = document.getElementById('policyValidation');
    const errors = [];
    const payload = collectPayload();
    if (!payload.name) errors.push('策略名称不能为空');
    if (!payload.users.length) errors.push('授权用户不能为空（空规则不会被保存或放行）');
    if (!payload.file_types.length) errors.push('文件类型不能为空（空规则不会被保存或放行）');
    if (payload.start_at && payload.end_at && payload.end_at <= payload.start_at)
        errors.push('结束时间必须晚于开始时间');
    if (payload.end_at && payload.end_at <= Date.now() / 1000)
        errors.push('结束时间已过，策略一经创建即失效');
    if (!payload.max_downloads || Number.isNaN(payload.max_downloads))
        errors.push('取件次数必须是正整数（勾选不限次数可跳过）');
    else if (payload.max_downloads === 0)
        errors.push('取件次数不能为 0');

    box.innerHTML = errors.map(e => `<div class="val-err">⛔ ${escapeHtml(e)}</div>`).join('');
    return errors.length === 0;
}

function updateAutoDescription() {
    const payload = collectPayload();
    const userPart = payload.users.includes('*') ? '所有用户' : payload.users.join('、') || '（未选择用户）';
    const typePart = payload.file_types.includes('*') ? '所有文件类型'
        : (payload.file_types.length ? payload.file_types.map(t => '.' + t).join('、') : '（未选择类型）');
    const timePart = `${payload.start_at ? formatTs(payload.start_at) : '即时'} ~ ${payload.end_at ? formatTs(payload.end_at) : '长期'}`;
    const quotaPart = payload.max_downloads === -1 ? '不限次数' : `${payload.max_downloads || 0} 次取件`;
    document.getElementById('autoDescription').textContent =
        `策略说明预览：[${payload.enabled ? '启用中' : '已停用'}] 允许 ${userPart} 在 ${timePart} 下载 ${typePart}，${quotaPart}。`;
}

async function savePolicy() {
    if (!liveValidate()) {
        alert('策略配置存在问题，请先根据页面上的红色提示修正');
        return;
    }
    const payload = collectPayload();
    const id = document.getElementById('policyId').value;
    const url = id ? `${API_BASE}/policies/${id}` : `${API_BASE}/policies`;
    const method = id ? 'PUT' : 'POST';
    showLoading(id ? '更新策略...' : '创建策略...');
    try {
        const r = await fetch(url, { method, headers: authHeaders(), body: JSON.stringify(payload) });
        const data = await r.json();
        if (r.ok) {
            closeEditor();
            await loadPolicies();
            await loadHistory();
        } else if (r.status === 409) {
            const conflicts = (data.conflicts || []).map(c =>
                `⛔ ${c.message}（重叠维度：${c.dimensions.join('、')}）`).join('\n');
            alert(`策略冲突，未保存：\n${data.error}\n\n${conflicts}\n\n请调整授权范围，或先停用冲突策略。`);
        } else {
            document.getElementById('policyValidation').innerHTML =
                `<div class="val-err">⛔ ${escapeHtml(data.error || '保存失败')}</div>`;
        }
    } catch (e) {
        alert(`保存失败: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function togglePolicy(id, enabled) {
    const p = policies.find(x => x.id === id);
    if (!p || !confirm(`确定要${enabled ? '启用' : '停用'}策略「${p.name}」吗？\n`
        + (enabled ? '启用后命中范围的下载将被放行。' : '停用后，本可命中该策略的下载会被拒绝并提示“策略已停用”。'))) return;
    showLoading(enabled ? '启用中...' : '停用中...');
    try {
        const r = await fetch(`${API_BASE}/policies/${id}`, {
            method: 'PATCH', headers: authHeaders(), body: JSON.stringify({ enabled }),
        });
        const data = await r.json();
        if (!r.ok) {
            if (r.status === 409) {
                const conflicts = (data.conflicts || []).map(c => `⛔ ${c.message}`).join('\n');
                alert(`无法启用：${data.error}\n\n${conflicts}`);
            } else {
                alert(data.error || '操作失败');
            }
        }
        await loadPolicies();
        await loadHistory();
    } catch (e) {
        alert(`操作失败: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function removePolicy(id) {
    const p = policies.find(x => x.id === id);
    if (!p || !confirm(`确定删除策略「${p.name}」吗？删除后立即生效且不可恢复。`)) return;
    showLoading('删除中...');
    try {
        const r = await fetch(`${API_BASE}/policies/${id}`, { method: 'DELETE', headers: authHeaders() });
        if (!r.ok) { alert((await r.json()).error || '删除失败'); }
        await loadPolicies();
        await loadHistory();
    } catch (e) {
        alert(`删除失败: ${e.message}`);
    } finally {
        hideLoading();
    }
}

async function resetUsage(id) {
    const p = policies.find(x => x.id === id);
    if (!p || !confirm(`确定将策略「${p.name}」的已用取件次数清零吗？`)) return;
    try {
        const r = await fetch(`${API_BASE}/policies/${id}/reset-usage`, { method: 'POST', headers: authHeaders() });
        if (!r.ok) { alert((await r.json()).error || '操作失败'); }
        await loadPolicies();
        await loadHistory();
    } catch (e) {
        alert(`操作失败: ${e.message}`);
    }
}

// ---------------------------------------------------------------------------
// 命中结果预览
// ---------------------------------------------------------------------------
async function quickPreview(id) {
    const p = policies.find(x => x.id === id);
    if (!p) return;
    await openPreview({
        name: p.name, description: p.description,
        users: p.users, file_types: p.file_types,
        start_at: p.start_at, end_at: p.end_at,
        max_downloads: p.max_downloads, used_downloads: p.used_downloads,
    }, null);
}

async function runPreview() {
    if (!liveValidate()) {
        alert('策略配置存在问题，请先修正后再预览');
        return;
    }
    await openPreview(collectPayload(), null);
}

async function addPreviewScenario() {
    if (!lastValidPreviewPayload) return;
    const username = document.getElementById('previewUser').value.trim();
    const filename = document.getElementById('previewFile').value.trim();
    const usedRaw = document.getElementById('previewUsed').value.trim();
    if (!username || !filename) { alert('请填写模拟用户名和文件名'); return; }
    const scenarios = buildDefaultScenarios(lastValidPreviewPayload);
    scenarios.push({
        label: `自定义：${username} × ${filename}`,
        username, filename,
        simulated_used: usedRaw === '' ? undefined : parseInt(usedRaw, 10),
    });
    document.getElementById('previewUser').value = '';
    document.getElementById('previewFile').value = '';
    document.getElementById('previewUsed').value = '';
    await openPreview(lastValidPreviewPayload, scenarios);
}

function buildDefaultScenarios(payload) {
    const now = Date.now() / 1000;
    const okUser = payload.users.find(u => u !== '*') || 'admin';
    const okType = payload.file_types.find(t => t !== '*') || 'pdf';
    const scenarios = [
        { label: '范围内用户 × 授权类型（预期放行）', username: okUser, filename: `示例文件.${okType}`, at: now },
        { label: '范围外用户（预期拒绝）', username: '__不在名单的用户__', filename: `示例文件.${okType}`, at: now },
        { label: '未授权文件类型（预期拒绝）', username: okUser, filename: '示例文件.notauth', at: now },
    ];
    if (payload.max_downloads !== -1 && payload.max_downloads != null) {
        scenarios.push({
            label: `取件次数已满（已用 ${payload.max_downloads} 次，预期拒绝）`,
            username: okUser, filename: `示例文件.${okType}`, simulated_used: payload.max_downloads, at: now,
        });
    }
    return scenarios;
}

async function openPreview(payload, scenarios) {
    showLoading('计算命中结果...');
    try {
        const body = { ...payload };
        if (scenarios) body.scenarios = scenarios;
        const r = await fetch(`${API_BASE}/policies/preview`, {
            method: 'POST', headers: authHeaders(), body: JSON.stringify(body),
        });
        const data = await r.json();
        if (!r.ok) {
            alert(`预览失败：${data.error || '配置无效'}`);
            hideLoading();
            return;
        }
        lastValidPreviewPayload = payload;
        document.getElementById('previewDescription').textContent = data.description;
        document.getElementById('previewResults').innerHTML = data.results.map(res => `
            <div class="preview-item ${res.allowed ? 'allow' : 'deny'}">
                <div class="preview-head">
                    <span class="preview-verdict">${res.allowed ? '✅ 放行' : '⛔ 拒绝'}</span>
                    <span class="preview-label">${escapeHtml(res.label || '')}</span>
                </div>
                <div class="preview-meta">用户：<strong>${escapeHtml(res.username)}</strong> · 文件：<strong>${escapeHtml(res.filename)}</strong></div>
                <div class="preview-reason">${escapeHtml(res.message)}</div>
                ${res.remaining_downloads != null ? `<div class="preview-quota">剩余取件次数：${res.remaining_downloads}</div>` : ''}
            </div>
        `).join('');
        document.getElementById('previewModal').classList.add('active');
    } catch (e) {
        alert(`预览失败: ${e.message}`);
    } finally {
        hideLoading();
    }
}
function closePreview() {
    document.getElementById('previewModal').classList.remove('active');
}

// ---------------------------------------------------------------------------
// 历史核对
// ---------------------------------------------------------------------------
async function loadHistory() {
    if (!(await TokenManager.isValid())) return;
    const type = document.getElementById('historyTypeFilter').value;
    const decision = document.getElementById('historyDecisionFilter').value;
    const params = new URLSearchParams();
    if (type) params.set('event_type', type);
    if (decision) params.set('decision', decision);
    try {
        const r = await fetch(`${API_BASE}/policies/history?${params.toString()}`, {
            headers: { Authorization: `Bearer ${TokenManager.get()}` },
        });
        if (!r.ok) return;
        const logs = await r.json();
        const list = document.getElementById('historyList');
        if (!logs.length) {
            list.innerHTML = '<p class="empty-msg">暂无历史记录</p>';
            return;
        }
        list.innerHTML = logs.map(l => {
            const typeLabel = l.event_type === 'policy_config' ? '⚙️ 配置' : '⬇️ 下载判定';
            const decisionCls = l.decision === 'allow' ? 'valid' : l.decision === 'deny' ? 'invalid' : 'pending';
            const decisionLabel = { allow: '放行', deny: '拒绝', info: '信息' }[l.decision] || l.decision;
            const scope = l.source === 'public_share' ? '公开分享页'
                : l.source === 'directory' ? '目录页'
                : l.source === 'policy_center' ? '策略中心' : (l.source || '-');
            return `
            <div class="history-item">
                <div class="history-head">
                    <span>${typeLabel}</span>
                    <span class="share-item-status ${decisionCls}">${decisionLabel}</span>
                    <span class="history-time">${formatTs(l.ts)}</span>
                </div>
                <div class="history-msg">${escapeHtml(l.message || '')}</div>
                <div class="history-meta">
                    <span>来源：${scope}</span>
                    ${l.subject ? `<span>授权主体：${escapeHtml(l.subject)}</span>` : ''}
                    ${l.requester ? `<span>取件人：${escapeHtml(l.requester)}</span>` : ''}
                    ${l.filename ? `<span>文件：${escapeHtml(l.filename)}</span>` : ''}
                    ${l.actor ? `<span>操作人：${escapeHtml(l.actor)}</span>` : ''}
                    ${l.reason ? `<span>原因码：${escapeHtml(l.reason)}</span>` : ''}
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        document.getElementById('historyList').innerHTML = `<p class="empty-msg">历史加载失败: ${escapeHtml(e.message)}</p>`;
    }
}
