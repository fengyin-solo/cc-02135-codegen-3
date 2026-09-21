"""下载授权策略中心：策略模型、校验、冲突检测与统一授权判定引擎

所有下载入口（文件库目录、公开分享页、重新进入的分享页）都必须通过
evaluate_download() 得到判定结果，保证不同入口的结论一致。
"""
import re
import time
import logging
from datetime import datetime

from database import get_db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 判定原因码（错误反馈与历史核对共用同一套词汇）
# ---------------------------------------------------------------------------
ALLOW = 'allow'
DENY = 'deny'

REASON_NO_POLICY_LEGACY = 'no_policy_legacy'        # 系统尚未配置任何策略，沿用默认放行
REASON_NO_MATCHING_POLICY = 'no_matching_policy'   # 没有任何策略覆盖该请求
REASON_POLICY_DISABLED = 'policy_disabled'         # 仅有已停用策略命中
REASON_POLICY_CONFLICT = 'policy_conflict'         # 多条启用策略同时命中（重叠）
REASON_TIME_OUTSIDE_WINDOW = 'time_outside_window' # 用户/类型匹配但不在时间范围内
REASON_QUOTA_EXHAUSTED = 'quota_exhausted'         # 取件次数已用尽

REASON_TEXT = {
    REASON_NO_POLICY_LEGACY: '系统尚未配置授权策略，按默认规则放行（不限制）',
    REASON_NO_MATCHING_POLICY: '没有适用于该用户与文件类型的授权策略',
    REASON_POLICY_DISABLED: '匹配的授权策略已停用，不予放行',
    REASON_POLICY_CONFLICT: '存在多条相互重叠的启用策略，判定冲突，不予放行',
    REASON_TIME_OUTSIDE_WINDOW: '当前时间不在策略允许的时间范围内',
    REASON_QUOTA_EXHAUSTED: '该策略允许的取件次数已用尽',
}


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def split_csv(value):
    """把逗号/换行/空白分隔的字符串拆成干净的列表"""
    if value is None:
        return []
    if isinstance(value, list):
        raw_items = value
    else:
        raw_items = re.split(r'[,，\n;；\s]+', str(value))
    return [str(item).strip() for item in raw_items if str(item).strip()]


def normalize_usernames(value):
    """用户名按原样保留大小写比较时统一小写"""
    return [name.lower() for name in split_csv(value)]


def normalize_extensions(value):
    """扩展名：去点、小写、只保留字母数字"""
    result = []
    for ext in split_csv(value):
        ext = ext.lstrip('.').lower()
        if ext:
            result.append(ext)
    return result


def parse_hhmm(value):
    """解析 HH:MM，返回分钟数；非法返回 None；空串返回 None（表示不限制）"""
    if value is None or str(value).strip() == '':
        return None
    text = str(value).strip()
    match = re.fullmatch(r'(\d{1,2}):(\d{2})', text)
    if not match:
        raise ValueError(f'时间格式不正确：{text}（应为 HH:MM）')
    hour, minute = int(match.group(1)), int(match.group(2))
    if hour > 23 or minute > 59:
        raise ValueError(f'时间超出范围：{text}')
    return hour * 60 + minute


def _as_minute(value):
    """把数据库/入参中的时间窗边界统一成“分钟整数”，空值返回 None"""
    if value is None or value == '':
        return None
    return int(value)


def window_to_intervals(start_min, end_min):
    """把每日时间窗展开为 0-1440 分钟轴上的若干线性区间（支持跨午夜）"""
    start_min = _as_minute(start_min)
    end_min = _as_minute(end_min)
    if start_min is None and end_min is None:
        return [(0, 1440)]
    if start_min is None:
        start_min = 0
    if end_min is None:
        end_min = 1440
    if start_min == end_min:
        return [(0, 1440)]
    if start_min < end_min:
        return [(start_min, end_min)]
    # 跨午夜，如 22:00-06:00
    return [(start_min, 1440), (0, end_min)]


def windows_overlap(start_a, end_a, start_b, end_b):
    """判断两个每日时间窗是否重叠"""
    intervals_a = window_to_intervals(start_a, end_a)
    intervals_b = window_to_intervals(start_b, end_b)
    for a_start, a_end in intervals_a:
        for b_start, b_end in intervals_b:
            if a_start < b_end and b_start < a_end:
                return True
    return False


def current_minute(now=None):
    if now is None:
        now = datetime.now()
    return now.hour * 60 + now.minute


def extract_extension(filename):
    if '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[1].lower()


def row_to_policy(row):
    """数据库行转成对外的策略字典"""
    start_min = _as_minute(row['start_time'])
    end_min = _as_minute(row['end_time'])
    return {
        'id': row['id'],
        'name': row['name'],
        'description': row['description'] or '',
        'usernames': split_csv(row['usernames']),
        'extensions': split_csv(row['extensions']),
        'start_time': _minute_to_hhmm(start_min) if start_min is not None else None,
        'end_time': _minute_to_hhmm(end_min) if end_min is not None else None,
        'max_downloads': row['max_downloads'],
        'enabled': bool(row['enabled']),
        'created_by': row['created_by'],
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
    }


def _minute_to_hhmm(value):
    return f'{value // 60:02d}:{value % 60:02d}'


def get_all_policies(conn):
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM download_policies ORDER BY id ASC')
    return [dict(row) for row in cursor.fetchall()]


# ---------------------------------------------------------------------------
# 策略说明
# ---------------------------------------------------------------------------
def describe_policy(policy):
    """生成人类可读的策略说明"""
    users = policy.get('usernames') or []
    exts = policy.get('extensions') or []
    start = policy.get('start_time')
    end = policy.get('end_time')
    limit = policy.get('max_downloads')

    parts = []
    parts.append(f'用户：{"、".join(users) if users else "任意已登录用户"}')
    parts.append(f'文件类型：{"、".join(exts) if exts else "任意类型"}')
    if start or end:
        parts.append(f'允许时段：每日 {start or "00:00"} – {end or "24:00"}（可跨午夜）')
    else:
        parts.append('允许时段：全天')
    parts.append(f'取件次数：{limit} 次/人' if limit else '取件次数：不限')

    state = '启用中' if policy.get('enabled', True) else '已停用'
    return f'【{policy.get("name", "未命名策略")}｜{state}】' + '；'.join(parts)


# ---------------------------------------------------------------------------
# 配置层校验
# ---------------------------------------------------------------------------
def validate_policy_payload(data, conn, policy_id=None):
    """校验策略配置，返回 (clean_dict, errors)。errors 非空时不得落库。"""
    errors = []
    if not isinstance(data, dict):
        return None, ['请求数据格式不正确']

    name = str(data.get('name', '')).strip()
    if not name:
        errors.append('策略名称不能为空')
    if len(name) > 100:
        errors.append('策略名称不能超过 100 个字符')

    description = str(data.get('description', '') or '').strip()
    if len(description) > 500:
        errors.append('策略说明不能超过 500 个字符')

    # 用户维度
    usernames = normalize_usernames(data.get('usernames', ''))
    if usernames:
        cursor = conn.cursor()
        placeholders = ','.join('?' for _ in usernames)
        cursor.execute(
            f'SELECT LOWER(username) AS username FROM users WHERE LOWER(username) IN ({placeholders})',
            usernames
        )
        existing = {row['username'] for row in cursor.fetchall()}
        unknown = sorted(set(usernames) - existing)
        if unknown:
            errors.append(f'以下用户不存在：{"、".join(unknown)}')

    # 文件类型维度
    extensions = normalize_extensions(data.get('extensions', ''))
    for ext in extensions:
        if not re.fullmatch(r'[a-z0-9]{1,10}', ext):
            errors.append(f'文件类型不合法：{ext}（应为 1-10 位字母数字）')
            break

    # 时间范围维度
    try:
        start_min = parse_hhmm(data.get('start_time'))
        end_min = parse_hhmm(data.get('end_time'))
    except ValueError as exc:
        start_min = end_min = None
        errors.append(str(exc))

    # 取件次数维度：空 = 不限；否则正整数
    max_downloads = data.get('max_downloads', None)
    if max_downloads in ('', None):
        max_downloads = None
    else:
        try:
            max_downloads = int(max_downloads)
            if max_downloads <= 0:
                errors.append('取件次数必须为正整数（留空表示不限次数）')
        except (TypeError, ValueError):
            errors.append('取件次数必须为正整数（留空表示不限次数）')
            max_downloads = None

    # 空规则：四个维度一个都没限定，绝不能落库（否则会成为无约束放行）
    if not errors and not usernames and not extensions and start_min is None and end_min is None:
        errors.append('规则为空：至少需要限定用户、文件类型或时间范围中的一项，'
                      '否则等同于对所有人无条件放行，系统拒绝保存')

    clean = None
    if not errors:
        clean = {
            'name': name,
            'description': description,
            'usernames': usernames,
            'extensions': extensions,
            'start_min': start_min,
            'end_min': end_min,
            'max_downloads': max_downloads,
        }

    return clean, errors


def _scopes_intersect(policy_a, policy_b):
    """两条策略的 用户 × 文件类型 × 时间窗 是否存在交集"""
    users_a = [u.lower() for u in split_csv(policy_a['usernames'])]
    users_b = [u.lower() for u in split_csv(policy_b['usernames'])]
    if users_a and users_b and not (set(users_a) & set(users_b)):
        return False

    exts_a = normalize_extensions(policy_a['extensions'])
    exts_b = normalize_extensions(policy_b['extensions'])
    if exts_a and exts_b and not (set(exts_a) & set(exts_b)):
        return False

    return windows_overlap(
        policy_a['start_time'], policy_a['end_time'],
        policy_b['start_time'], policy_b['end_time']
    )


def find_overlaps(policy, conn, exclude_id=None):
    """找出与给定（尚未入库或已存在的）策略重叠的启用策略，用于冲突提示"""
    candidate = {
        'usernames': ','.join(policy['usernames']),
        'extensions': ','.join(policy['extensions']),
        'start_time': policy['start_min'],
        'end_time': policy['end_min'],
    }
    overlaps = []
    for other in get_all_policies(conn):
        if exclude_id is not None and other['id'] == exclude_id:
            continue
        if not other['enabled']:
            continue
        if _scopes_intersect(candidate, other):
            quota_note = ''
            if policy['max_downloads'] != other['max_downloads']:
                limit_a = policy['max_downloads'] or '不限'
                limit_b = other['max_downloads'] or '不限'
                quota_note = f'（取件次数限制不一致：{limit_a} vs {limit_b}）'
            overlaps.append({
                'id': other['id'],
                'name': other['name'],
                'quota_note': quota_note,
            })
    return overlaps


# ---------------------------------------------------------------------------
# 授权判定引擎（所有入口共用）
# ---------------------------------------------------------------------------
def _policy_matches_user_ext(policy, username, extension):
    users = [u.lower() for u in split_csv(policy['usernames'])]
    if users and username.lower() not in users:
        return False
    exts = normalize_extensions(policy['extensions'])
    if exts and extension not in exts:
        return False
    return True


def _policy_time_allows(policy, minute):
    """policy 为数据库原始行，start_time/end_time 以分钟数存储"""
    intervals = window_to_intervals(policy['start_time'], policy['end_time'])
    return any(start <= minute < end for start, end in intervals)


def _count_used(conn, username, policy_id):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT COUNT(*) AS cnt FROM policy_decision_log
        WHERE username = ? AND matched_policy_id = ?
          AND enforced = 1 AND decision = 'allow'
    ''', (username, policy_id))
    return cursor.fetchone()['cnt']


def evaluate_download(username, file_id, filename, source='directory',
                      enforced=True, now=None, conn=None):
    """统一授权判定。

    返回结构：
    {
      decision: 'allow' | 'deny',
      reason, reason_text, reason_detail,
      policy: {...} | None,
      used, limit, remaining,
      source, enforced, checked_at
    }
    """
    own_conn = conn is None
    if own_conn:
        conn = get_db()

    extension = extract_extension(filename)
    minute = current_minute(now)
    policies = get_all_policies(conn)

    result = {
        'decision': DENY,
        'reason': None,
        'reason_text': '',
        'reason_detail': '',
        'policy': None,
        'used': None,
        'limit': None,
        'remaining': None,
        'source': source,
        'enforced': bool(enforced),
        'username': username,
        'file_id': file_id,
        'filename': filename,
        'extension': extension,
        'checked_at': time.time(),
    }

    def finish(reason, detail='', policy=None, used=None):
        result['reason'] = reason
        result['reason_text'] = REASON_TEXT.get(reason, reason)
        result['reason_detail'] = detail
        result['policy'] = policy
        result['used'] = used
        if policy is not None:
            result['limit'] = policy['max_downloads']
            if policy['max_downloads'] is not None and used is not None:
                result['remaining'] = max(0, policy['max_downloads'] - used)
        # enforced=0（重新进入页面的预判）也留痕便于历史核对，但不参与取件次数统计
        record_decision(conn, result)
        conn.commit()
        if own_conn:
            conn.close()
        logger.info('授权判定 source=%s user=%s file=%s -> %s (%s)',
                    source, username, filename, result['decision'], reason)
        return result

    # 1) 系统中一条策略都没有：向后兼容，默认放行（带明确原因，便于核对）
    if not policies:
        result['decision'] = ALLOW
        return finish(REASON_NO_POLICY_LEGACY)

    enabled_full, enabled_user_ext = [], []
    disabled_full, disabled_user_ext = [], []

    for raw in policies:
        policy = row_to_policy(raw)
        if not _policy_matches_user_ext(policy, username, extension):
            continue
        bucket_full = enabled_full if policy['enabled'] else disabled_full
        bucket_ue = enabled_user_ext if policy['enabled'] else disabled_user_ext
        if _policy_time_allows(raw, minute):
            bucket_full.append((policy, raw))
        else:
            bucket_ue.append((policy, raw))

    # 2) 多条启用策略同时命中 -> 冲突，不放行
    if len(enabled_full) > 1:
        names = '、'.join(p['name'] for p, _ in enabled_full)
        return finish(REASON_POLICY_CONFLICT, f'同时命中：{names}')

    # 3) 唯一启用策略完整命中 -> 检查取件次数
    if len(enabled_full) == 1:
        policy, raw = enabled_full[0]
        used = _count_used(conn, username, policy['id'])
        if policy['max_downloads'] is not None and used >= policy['max_downloads']:
            return finish(
                REASON_QUOTA_EXHAUSTED,
                f'策略「{policy["name"]}」允许 {policy["max_downloads"]} 次，'
                f'已取件 {used} 次',
                policy=policy, used=used
            )
        result['decision'] = ALLOW
        return finish(
            'matched',
            f'命中策略「{policy["name"]}」' +
            (f'，已用 {used}/{policy["max_downloads"]} 次'
             if policy['max_downloads'] is not None else ''),
            policy=policy, used=used
        )

    # 4) 用户与类型匹配但当前不在时间窗内
    if enabled_user_ext:
        names = '、'.join(p['name'] for p, _ in enabled_user_ext)
        return finish(REASON_TIME_OUTSIDE_WINDOW, f'受策略「{names}」的允许时段限制')

    # 5) 只有停用策略匹配
    disabled_matches = disabled_full + disabled_user_ext
    if disabled_matches:
        names = '、'.join(p['name'] for p, _ in disabled_matches)
        return finish(REASON_POLICY_DISABLED,
                      f'匹配的策略「{names}」当前为停用状态')

    # 6) 没有任何策略覆盖该 用户 × 类型
    return finish(
        REASON_NO_MATCHING_POLICY,
        f'用户「{username}」对文件类型「{extension or "无扩展名"}」没有任何授权策略'
    )


def record_decision(conn, result):
    """把一次判定写入历史（用于历史核对与取件次数统计）"""
    policy = result.get('policy') or {}
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO policy_decision_log
            (username, file_id, filename, extension, source,
             decision, reason, reason_detail,
             matched_policy_id, matched_policy_name, enforced)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        result.get('username'),
        result.get('file_id'),
        result.get('filename'),
        result.get('extension'),
        result.get('source'),
        result.get('decision'),
        result.get('reason'),
        result.get('reason_detail'),
        policy.get('id'),
        policy.get('name'),
        1 if result.get('enforced') else 0,
    ))
    return cursor.lastrowid


def public_decision(result):
    """统一的判定结果对外结构（错误反馈 / 预览 / 各下载入口共用，保证口径一致）"""
    return {
        'decision': result['decision'],
        'allowed': result['decision'] == ALLOW,
        'reason': result['reason'],
        'reason_text': result['reason_text'],
        'reason_detail': result['reason_detail'],
        'source': result['source'],
        'used': result['used'],
        'limit': result['limit'],
        'remaining': result['remaining'],
        'policy': {
            'id': result['policy']['id'],
            'name': result['policy']['name'],
            'description': result['policy'].get('description', ''),
        } if result.get('policy') else None,
    }
