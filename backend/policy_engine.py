"""下载授权策略引擎

负责：
- 策略规则的解析与校验（空规则、非法时间范围等一律拒绝）
- 冲突检测（同维度授权范围重叠的启用中策略）
- 授权判定（用户 × 文件类型 × 时间范围 × 取件次数）
- 策略说明（人类可读的策略描述）与命中结果预览
- 判定/配置历史落库，供事后核对

判定的安全原则（缺一不可）：
1. 空规则永远不放行：用户列表或文件类型列表为空的策略无法保存；
2. 系统中不存在任何启用策略时，视为“授权中心未启用/已全部停用”，下载被拒绝并解释原因；
3. 令牌缺失/失效先于策略判定失败；
4. 命中停用策略、不在时间窗口、次数用完等均给出明确 reason。

目录页（直连下载）、公开页（分享链接下载）、重新进入的页面使用同一套
evaluate_* 纯判定逻辑，因此结果一致。
"""
import json
import time
import uuid
import sqlite3
import logging
from datetime import datetime

from database import get_db

logger = logging.getLogger(__name__)

WILDCARD = '*'
PREVIEW_USER = '__preview__'

# 判定原因码（前端可据此稳定地展示文案）
REASON_NO_POLICIES = 'no_active_policies'        # 没有任何启用中的策略（中心未启用/全部停用）
REASON_TOKEN_MISSING = 'token_missing'           # 未提供令牌
REASON_TOKEN_INVALID = 'token_invalid'           # 令牌失效或过期
REASON_POLICY_DISABLED = 'policy_disabled'        # 只有停用策略匹配
REASON_OUTSIDE_WINDOW = 'outside_time_window'    # 不在策略时间范围内
REASON_USER_FORBIDDEN = 'user_not_authorized'    # 用户不在授权名单
REASON_TYPE_FORBIDDEN = 'file_type_not_authorized'  # 文件类型不在授权范围
REASON_QUOTA_EXHAUSTED = 'download_quota_exhausted'  # 取件次数已用完
REASON_CONFLICT = 'policy_conflict'              # 多条启用策略同时命中（配置冲突）
REASON_FILE_NOT_FOUND = 'file_not_found'
REASON_NOT_ENFORCED = 'policy_center_not_configured'  # 中心尚未配置任何策略（兼容模式）


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def file_extension(filename):
    """取小写扩展名（无扩展名返回空串）"""
    if not filename or '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[1].lower()


def _parse_json_list(raw):
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return value if isinstance(value, list) else []


def normalize_entry_list(values, field_name, now=None):
    """规范化“用户列表 / 文件类型列表”

    - 去除空白、统一小写（文件类型）/去首尾空格（用户名）
    - 空列表直接拒绝（空规则不能放行也不能保存）
    """
    if values is None or not isinstance(values, list):
        raise PolicyValidationError(f'{field_name}必须是数组，且不能为空')

    cleaned = []
    for item in values:
        if not isinstance(item, str):
            raise PolicyValidationError(f'{field_name}只能包含字符串')
        item = item.strip()
        if not item:
            continue
        cleaned.append(item)

    if not cleaned:
        raise PolicyValidationError(f'{field_name}不能为空（空规则不会被保存或放行）')

    # 文件类型统一小写、去掉可能的前导点
    if field_name == '文件类型':
        cleaned = [ext.lstrip('.').lower() for ext in cleaned]

    if len(cleaned) != len(set(cleaned)):
        raise PolicyValidationError(f'{field_name}存在重复项')

    return cleaned


def normalize_time_window(start_at, end_at, now=None):
    """规范化时间窗口，允许两端为空表示不限"""
    now = now if now is not None else time.time()

    start_at = _to_epoch(start_at, '开始时间')
    end_at = _to_epoch(end_at, '结束时间')

    if start_at is not None and end_at is not None and end_at <= start_at:
        raise PolicyValidationError('时间范围无效：结束时间必须晚于开始时间')

    if end_at is not None and end_at <= now:
        raise PolicyValidationError('时间范围无效：结束时间已过，策略一经创建即失效')

    return start_at, end_at


def _to_epoch(value, label):
    if value is None or value == '':
        return None
    try:
        epoch = float(value)
    except (TypeError, ValueError):
        raise PolicyValidationError(f'{label}格式无效，请使用时间戳（秒）')
    return epoch


def normalize_max_downloads(value):
    """取件次数：正整数；None/负数表示不限制（-1 与前端保持兼容）"""
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise PolicyValidationError('取件次数必须是正整数（-1 表示不限）')
    if number < 0:
        return None
    if number == 0:
        raise PolicyValidationError('取件次数不能为 0（该策略将永远无法放行）')
    return number


# ---------------------------------------------------------------------------
# 异常与策略数据对象
# ---------------------------------------------------------------------------

class PolicyValidationError(ValueError):
    """策略配置本身不合法（空规则、非法时间等）"""


class PolicyConflictError(ValueError):
    """策略与其它启用中策略授权范围重叠"""
    def __init__(self, message, conflicts=None):
        super().__init__(message)
        self.conflicts = conflicts or []


class Policy:
    """一条授权策略的内存表示，判定逻辑全部挂在这里"""

    def __init__(self, row):
        self.id = row['id']
        self.name = row['name']
        self.description = row['description']
        self.users = _parse_json_list(row['users_json'])
        self.file_types = _parse_json_list(row['file_types_json'])
        self.start_at = row['start_at']
        self.end_at = row['end_at']
        self.max_downloads = row['max_downloads']
        self.used_downloads = row['used_downloads'] or 0
        self.enabled = bool(row['enabled'])

    # ---- 范围匹配 ----
    def match_user(self, username):
        return WILDCARD in self.users or username in self.users

    def match_type(self, ext):
        if WILDCARD in self.file_types:
            return True
        # 无扩展名文件：只有显式通配才能匹配，避免把未知类型偷偷放行
        return bool(ext) and ext in self.file_types

    def in_time_window(self, at=None):
        at = at if at is not None else time.time()
        if self.start_at is not None and at < self.start_at:
            return False
        if self.end_at is not None and at > self.end_at:
            return False
        return True

    def quota_remaining(self):
        if self.max_downloads is None:
            return None
        return max(0, self.max_downloads - self.used_downloads)

    def scope_matches(self, username, ext, at=None):
        """授权范围（用户×类型×时间）是否命中，不看启停与次数"""
        return self.match_user(username) and self.match_type(ext) and self.in_time_window(at)


# ---------------------------------------------------------------------------
# 存储层
# ---------------------------------------------------------------------------

def row_to_dict(row):
    return dict(row) if isinstance(row, sqlite3.Row) else row


def get_policy(policy_id, conn=None):
    own = conn is None
    conn = conn or get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM download_policies WHERE id = ?', (policy_id,))
    row = cur.fetchone()
    if own:
        conn.close()
    return Policy(row) if row else None


def list_policies(enabled_only=False, conn=None):
    own = conn is None
    conn = conn or get_db()
    cur = conn.cursor()
    if enabled_only:
        cur.execute('SELECT * FROM download_policies WHERE enabled = 1 ORDER BY created_at DESC')
    else:
        cur.execute('SELECT * FROM download_policies ORDER BY created_at DESC')
    rows = cur.fetchall()
    if own:
        conn.close()
    return [Policy(r) for r in rows]


def serialize_policy(policy, *, conflicts=None, now=None):
    """对外展示的策略结构"""
    now = now or time.time()
    return {
        'id': policy.id,
        'name': policy.name,
        'description': policy.description or build_description(policy),
        'users': policy.users,
        'file_types': policy.file_types,
        'start_at': policy.start_at,
        'end_at': policy.end_at,
        'max_downloads': policy.max_downloads,
        'used_downloads': policy.used_downloads,
        'remaining_downloads': policy.quota_remaining(),
        'enabled': policy.enabled,
        'time_state': _time_state(policy, now),
        'conflicts': conflicts or [],
    }


def _time_state(policy, now):
    if not policy.enabled:
        return 'disabled'
    if policy.start_at is not None and now < policy.start_at:
        return 'pending'
    if policy.end_at is not None and now > policy.end_at:
        return 'expired'
    return 'active'


# ---------------------------------------------------------------------------
# 策略说明
# ---------------------------------------------------------------------------

def _format_scope_list(items, all_label, formatter=lambda x: x):
    if WILDCARD in items:
        return all_label
    return '、'.join(formatter(i) for i in items)


def _format_ts(epoch):
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M')


def build_description(policy):
    """生成人类可读的策略说明"""
    user_part = _format_scope_list(policy.users, '所有用户')
    type_part = _format_scope_list(policy.file_types, '所有文件类型', lambda e: f'.{e}')
    quota = '不限次数' if policy.max_downloads is None else f'最多 {policy.max_downloads} 次取件（已用 {policy.used_downloads} 次）'

    if policy.start_at is None and policy.end_at is None:
        time_part = '长期有效'
    else:
        time_part = f'{_format_ts(policy.start_at) or "即时"} 至 {_format_ts(policy.end_at) or "长期"}'

    state = '启用中' if policy.enabled else '已停用'
    return f'[{state}] 允许 {user_part} 在 {time_part} 下载 {type_part}，{quota}。'


# ---------------------------------------------------------------------------
# 冲突检测
# ---------------------------------------------------------------------------

def _time_overlap(a, b):
    """两个 [start, end]（None 表示无限）是否重叠；不重叠返回 False"""
    a_start, a_end = a.start_at, a.end_at
    b_start, b_end = b.start_at, b.end_at
    if a_end is not None and b_start is not None and a_end <= b_start:
        return False
    if b_end is not None and a_start is not None and b_end <= a_start:
        return False
    return True


def _list_overlap(a, b):
    if WILDCARD in a or WILDCARD in b:
        return True
    return bool(set(a) & set(b))


def policies_conflict(a, b):
    """两条策略在 用户×类型×时间 三个维度都存在交集即冲突"""
    return (
        _list_overlap(a.users, b.users)
        and _list_overlap(a.file_types, b.file_types)
        and _time_overlap(a, b)
    )


def find_conflicts(candidate, others, *, candidate_enabled=True):
    """返回 candidate 与 others 中启用策略的冲突明细"""
    if not candidate_enabled:
        return []
    conflicts = []
    for other in others:
        if not other.enabled or other.id == candidate.id:
            continue
        overlap_users = _list_overlap(candidate.users, other.users)
        overlap_types = _list_overlap(candidate.file_types, other.file_types)
        overlap_time = _time_overlap(candidate, other)
        if overlap_users and overlap_types and overlap_time:
            conflicts.append({
                'policy_id': other.id,
                'policy_name': other.name,
                'dimensions': [d for d, hit in (
                    ('用户', overlap_users), ('文件类型', overlap_types), ('时间范围', overlap_time)
                ) if hit],
                'message': f'与启用中策略「{other.name}」在 用户、文件类型、时间范围 上重叠，命中结果不确定',
            })
    return conflicts


def assert_no_conflict(candidate, conn=None, *, candidate_enabled=True):
    conflicts = find_conflicts(candidate, list_policies(conn=conn), candidate_enabled=candidate_enabled)
    if conflicts:
        raise PolicyConflictError(
            '授权范围与已有启用策略重叠，请调整范围或先停用冲突策略',
            conflicts=conflicts,
        )


def current_conflicts(conn=None):
    """全量扫描：返回 policy_id -> 冲突列表（停用再启用等场景下的存量冲突）"""
    enabled = list_policies(enabled_only=True, conn=conn)
    result = {}
    for policy in enabled:
        hits = find_conflicts(policy, enabled)
        if hits:
            result[policy.id] = hits
    return result


# ---------------------------------------------------------------------------
# CRUD（含保存前校验：空规则/冲突一律不落库）
# ---------------------------------------------------------------------------

def prepare_policy_payload(data, *, now=None):
    """校验并规范化前端提交的策略字段"""
    now = now or time.time()
    if not isinstance(data, dict):
        raise PolicyValidationError('无效的请求数据')

    name = (data.get('name') or '').strip()
    if not name:
        raise PolicyValidationError('策略名称不能为空')
    if len(name) > 80:
        raise PolicyValidationError('策略名称不能超过 80 个字符')

    users = normalize_entry_list(data.get('users'), '授权用户')
    file_types = normalize_entry_list(data.get('file_types'), '文件类型')
    start_at, end_at = normalize_time_window(data.get('start_at'), data.get('end_at'), now=now)
    max_downloads = normalize_max_downloads(data.get('max_downloads'))

    description = data.get('description')
    if description is not None:
        description = str(description).strip() or None

    return {
        'name': name,
        'description': description,
        'users': users,
        'file_types': file_types,
        'start_at': start_at,
        'end_at': end_at,
        'max_downloads': max_downloads,
    }


def create_policy(payload, created_by, *, enabled=True, now=None, conn=None):
    own = conn is None
    conn = conn or get_db()
    policy_id = uuid.uuid4().hex

    # 先用内存对象做冲突预检，确认无冲突再落库（空规则/冲突一律不保存）
    probe = _temp_policy(policy_id, payload, enabled=enabled)
    assert_no_conflict(probe, conn=conn, candidate_enabled=enabled)

    cur = conn.cursor()
    cur.execute('''
        INSERT INTO download_policies
            (id, name, description, users_json, file_types_json, start_at, end_at,
             max_downloads, used_downloads, enabled, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    ''', (
        policy_id, payload['name'], payload['description'],
        json.dumps(payload['users'], ensure_ascii=False),
        json.dumps(payload['file_types'], ensure_ascii=False),
        payload['start_at'], payload['end_at'], payload['max_downloads'],
        1 if enabled else 0, created_by,
    ))
    conn.commit()
    policy = get_policy(policy_id, conn=conn)
    if own:
        conn.close()
    return policy


def _temp_policy(policy_id, payload, *, enabled=True, used_downloads=0):
    """依据已校验 payload 构造一个内存 Policy，用于冲突预检/预览"""
    class _Row(dict):
        def __getitem__(self, key):
            return self.get(key)

    row = _Row(
        id=policy_id,
        name=payload['name'],
        description=payload.get('description'),
        users_json=json.dumps(payload['users'], ensure_ascii=False),
        file_types_json=json.dumps(payload['file_types'], ensure_ascii=False),
        start_at=payload.get('start_at'),
        end_at=payload.get('end_at'),
        max_downloads=payload.get('max_downloads'),
        used_downloads=used_downloads,
        enabled=1 if enabled else 0,
    )
    return Policy(row)


def update_policy(policy_id, payload, *, enabled=None, now=None, conn=None):
    own = conn is None
    conn = conn or get_db()
    policy = get_policy(policy_id, conn=conn)
    if not policy:
        if own:
            conn.close()
        return None

    target_enabled = policy.enabled if enabled is None else enabled
    probe = _temp_policy(policy_id, payload, enabled=target_enabled,
                         used_downloads=policy.used_downloads)
    assert_no_conflict(probe, conn=conn, candidate_enabled=target_enabled)

    cur = conn.cursor()
    cur.execute('''
        UPDATE download_policies
        SET name=?, description=?, users_json=?, file_types_json=?, start_at=?, end_at=?,
            max_downloads=?, enabled=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=?
    ''', (
        payload['name'], payload['description'],
        json.dumps(payload['users'], ensure_ascii=False),
        json.dumps(payload['file_types'], ensure_ascii=False),
        payload['start_at'], payload['end_at'], payload['max_downloads'],
        1 if target_enabled else 0, policy_id,
    ))
    conn.commit()
    updated = get_policy(policy_id, conn=conn)
    if own:
        conn.close()
    return updated


def set_enabled(policy_id, enabled, conn=None):
    own = conn is None
    conn = conn or get_db()
    policy = get_policy(policy_id, conn=conn)
    if not policy:
        if own:
            conn.close()
        return None
    if enabled:
        # 启用前：时间窗口仍有效？与其它启用策略冲突？
        now = time.time()
        if policy.end_at is not None and policy.end_at <= now:
            raise PolicyValidationError('该策略的时间窗口已结束，无法启用（请先修改结束时间）')
        assert_no_conflict(policy, conn=conn, candidate_enabled=True)
    cur = conn.cursor()
    cur.execute('UPDATE download_policies SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                (1 if enabled else 0, policy_id))
    conn.commit()
    policy = get_policy(policy_id, conn=conn)
    if own:
        conn.close()
    return policy


def delete_policy(policy_id, conn=None):
    own = conn is None
    conn = conn or get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM download_policies WHERE id = ?', (policy_id,))
    deleted = cur.rowcount
    conn.commit()
    if own:
        conn.close()
    return deleted > 0


def reset_usage(policy_id, conn=None):
    own = conn is None
    conn = conn or get_db()
    cur = conn.cursor()
    cur.execute('UPDATE download_policies SET used_downloads = 0, updated_at=CURRENT_TIMESTAMP WHERE id = ?',
                (policy_id,))
    changed = cur.rowcount
    conn.commit()
    if own:
        conn.close()
    return changed > 0


# ---------------------------------------------------------------------------
# 核心判定
# ---------------------------------------------------------------------------

def _deny(reason, message, *, policies=None, disabled_matches=None, **extra):
    result = {
        'allowed': False,
        'reason': reason,
        'message': message,
        'matched_policy': None,
        'candidate_count': len(policies or []),
        'disabled_matches': [
            {'id': p.id, 'name': p.name, 'description': build_description(p)}
            for p in (disabled_matches or [])
        ],
        'enforced': bool(policies),
    }
    result.update(extra)
    return result


def _allow(policy, *, reason='allowed', message=None, enforced=True, remaining=None):
    return {
        'allowed': True,
        'reason': reason,
        'message': message or f'命中策略「{policy.name}」，允许下载',
        'matched_policy': serialize_policy(policy),
        'candidate_count': 0,
        'disabled_matches': [],
        'enforced': enforced,
        'remaining_downloads': remaining if remaining is not None else policy.quota_remaining(),
    }


def evaluate(username, filename, *, policies=None, at=None, used_override=None,
             include_disabled=True, conn=None):
    """纯判定：给定用户与文件名，返回授权结果

    used_override: 预览时用 {policy_id: 数字} 临时替换已用次数，不落库。
    """
    at = at if at is not None else time.time()
    ext = file_extension(filename)
    all_policies = policies if policies is not None else list_policies(conn=conn)
    enabled = [p for p in all_policies if p.enabled]
    disabled = [p for p in all_policies if not p.enabled]

    # 1) 中心从未配置过任何策略：兼容模式，按原有登录/分享校验放行（明确标注非策略放行）
    if not all_policies:
        return {
            'allowed': True,
            'reason': REASON_NOT_ENFORCED,
            'message': '下载授权策略中心尚未配置任何策略，沿用身份验证结果放行；配置策略后将以策略为准',
            'matched_policy': None,
            'candidate_count': 0,
            'disabled_matches': [],
            'enforced': False,
            'remaining_downloads': None,
        }

    # 2) 配置过策略但全部停用：策略停用期间绝不能放行，必须解释原因
    if not enabled:
        if include_disabled:
            hits = [p for p in disabled if p.scope_matches(username, ext, at)]
            if hits:
                return _deny(
                    REASON_POLICY_DISABLED,
                    f'匹配的授权策略「{hits[0].name}」当前已停用，请联系管理员启用后再试',
                    policies=enabled, disabled_matches=hits,
                )
        return _deny(
            REASON_NO_POLICIES,
            '所有下载授权策略均已停用，策略停用期间所有下载一律禁止，请先启用至少一条策略',
            policies=enabled,
        )

    def used(p):
        if used_override and p.id in used_override:
            return used_override[p.id]
        return p.used_downloads

    # 3) 范围命中（用户×类型×时间窗口内）
    in_scope = [p for p in enabled if p.match_user(username) and p.match_type(ext) and p.in_time_window(at)]

    # 4) 多条命中 = 配置冲突，拒绝并提示冲突对象
    if len(in_scope) > 1:
        return _deny(
            REASON_CONFLICT,
            '检测到 %d 条启用策略同时命中该请求，授权结果存在歧义，已拒绝下载。请调整重叠策略' % len(in_scope),
            policies=enabled,
            conflicts=[serialize_policy(p) for p in in_scope],
        )

    if len(in_scope) == 1:
        policy = in_scope[0]
        if policy.max_downloads is not None and used(policy) >= policy.max_downloads:
            return _deny(
                REASON_QUOTA_EXHAUSTED,
                f'策略「{policy.name}」的取件次数已用完（{used(policy)}/{policy.max_downloads}）',
                policies=enabled,
            )
        return _allow(policy)

    # 5) 无启用策略命中：按“停用命中 → 时间窗口 → 用户 → 类型”顺序解释原因
    disabled_hits = []
    if include_disabled:
        disabled_hits = [p for p in disabled if p.match_user(username) and p.match_type(ext) and p.in_time_window(at)]
        if disabled_hits:
            return _deny(
                REASON_POLICY_DISABLED,
                f'本可匹配的策略「{disabled_hits[0].name}」已停用，策略停用期间不放行',
                policies=enabled, disabled_matches=disabled_hits,
            )

    # 用“若忽略时间窗口”的匹配来定位是哪个维度不满足
    user_type_matches = [
        p for p in enabled if p.match_user(username) and p.match_type(ext) and not p.in_time_window(at)
    ]
    if user_type_matches:
        p = user_type_matches[0]
        window = f'{_format_ts(p.start_at) or "即时"} ~ {_format_ts(p.end_at) or "长期"}'
        return _deny(
            REASON_OUTSIDE_WINDOW,
            f'当前时间不在策略「{p.name}」允许的时间范围内（{window}）',
            policies=enabled,
        )

    # 区分是用户还是类型不满足
    type_ok = [p for p in enabled if p.match_type(ext)]
    if type_ok and not any(p.match_user(username) for p in type_ok):
        return _deny(
            REASON_USER_FORBIDDEN,
            f'用户「{username}」不在任何启用策略的授权用户范围内',
            policies=enabled,
        )

    user_ok = [p for p in enabled if p.match_user(username)]
    if user_ok and not any(p.match_type(ext) for p in user_ok):
        type_label = f'.{ext}' if ext else '无扩展名文件'
        return _deny(
            REASON_TYPE_FORBIDDEN,
            f'文件类型 {type_label} 不在用户「{username}」可用策略的授权文件类型范围内',
            policies=enabled,
        )

    return _deny(
        REASON_USER_FORBIDDEN,
        f'用户「{username}」与该文件类型的组合不在任何启用策略的授权范围内',
        policies=enabled,
    )


# ---------------------------------------------------------------------------
# 结果预览
# ---------------------------------------------------------------------------

def preview_with_policy(policy_dict, scenarios, *, now=None):
    """用一条（可能尚未保存的）策略对若干场景做命中预览"""
    now = now or time.time()
    candidate = _temp_policy(
        policy_dict.get('id') or PREVIEW_USER,
        policy_dict,
        enabled=True,
        used_downloads=policy_dict.get('used_downloads', 0),
    )

    results = []
    for sc in scenarios:
        sim_used = sc.get('simulated_used')
        used_override = {candidate.id: int(sim_used)} if sim_used is not None else None
        decision = evaluate(
            sc['username'], sc['filename'],
            policies=[candidate], at=sc.get('at') or now,
            used_override=used_override, include_disabled=False,
        )
        results.append({
            'label': sc.get('label'),
            'username': sc['username'],
            'filename': sc['filename'],
            'at': sc.get('at') or now,
            **{k: v for k, v in decision.items() if k in ('allowed', 'reason', 'message', 'remaining_downloads')},
        })
    return results


def default_preview_scenarios(users, file_types, *, sample_user=None, sample_type=None):
    """根据策略范围自动生成“会放行/会拒绝”的对照场景"""
    now = time.time()
    ok_user = sample_user or next((u for u in users if u != WILDCARD), 'admin')
    ok_type = sample_type or next((t for t in file_types if t != WILDCARD), 'pdf')
    bad_user = '__not_authorized_user__'
    bad_type = 'notauth'

    scenarios = [
        {'label': '范围内用户 × 授权类型（预期放行）', 'username': ok_user, 'filename': f'示例文件.{ok_type}', 'at': now},
        {'label': '范围外用户（预期拒绝）', 'username': bad_user, 'filename': f'示例文件.{ok_type}', 'at': now},
        {'label': '未授权文件类型（预期拒绝）', 'username': ok_user, 'filename': f'示例文件.{bad_type}', 'at': now},
    ]
    return scenarios


# ---------------------------------------------------------------------------
# 次数扣减（仅真实放行下载时调用）
# ---------------------------------------------------------------------------

def increment_usage(policy_id, conn=None):
    own = conn is None
    conn = conn or get_db()
    cur = conn.cursor()
    cur.execute('UPDATE download_policies SET used_downloads = used_downloads + 1 WHERE id = ?', (policy_id,))
    conn.commit()
    row = cur.execute('SELECT used_downloads, max_downloads FROM download_policies WHERE id = ?',
                      (policy_id,)).fetchone()
    if own:
        conn.close()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# 历史日志（判定核对 + 配置留痕）
# ---------------------------------------------------------------------------

def log_event(event_type, decision, *, policy_id=None, policy_name=None, subject=None,
              requester=None, file_id=None, filename=None, source=None, reason=None,
              message=None, detail=None, actor=None, conn=None):
    own = conn is None
    conn = conn or get_db()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO policy_logs
            (ts, event_type, decision, policy_id, policy_name, subject, requester,
             file_id, filename, source, reason, message, detail_json, actor)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        time.time(), event_type, decision, policy_id, policy_name, subject, requester,
        file_id, filename, source, reason, message,
        json.dumps(detail, ensure_ascii=False, default=str) if detail is not None else None,
        actor,
    ))
    conn.commit()
    if own:
        conn.close()


def list_logs(limit=100, event_type=None, decision=None, conn=None):
    own = conn is None
    conn = conn or get_db()
    cur = conn.cursor()
    sql = 'SELECT * FROM policy_logs WHERE 1=1'
    params = []
    if event_type:
        sql += ' AND event_type = ?'
        params.append(event_type)
    if decision:
        sql += ' AND decision = ?'
        params.append(decision)
    sql += ' ORDER BY id DESC LIMIT ?'
    params.append(min(int(limit), 500))
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    if own:
        conn.close()
    for r in rows:
        if r.get('detail_json'):
            try:
                r['detail'] = json.loads(r['detail_json'])
            except ValueError:
                r['detail'] = None
        else:
            r['detail'] = None
    return rows
