"""下载授权策略中心路由

- /api/policies/*            策略配置（增删改查、启停、次数重置）
- /api/policies/preview      策略命中结果预览（不落库、不扣次数）
- /api/policies/check/file   真实请求前的授权预检（目录页/重新进入页面）
- /api/policies/check/share  真实请求前的授权预检（公开分享页）
- /api/policies/history      判定与配置历史核对

管理接口仅登录用户可用；check/share 与分享页一样公开，
但判定逻辑与直连下载完全一致。
"""
import time
import logging

from flask import request, jsonify

from routes import policies_bp
from auth import login_required, get_username_from_token
from database import get_db
import policy_engine as pe
from routes.file_routes import get_token_from_request, get_share_link_info, is_share_valid

logger = logging.getLogger(__name__)


def _current_user():
    return get_username_from_token(get_token_from_request())


def _serialize_with_conflicts(policy, conflict_map, now):
    return pe.serialize_policy(policy, conflicts=conflict_map.get(policy.id, []), now=now)


# ---------------------------------------------------------------------------
# 元数据（用户列表、常用类型），供配置表单使用
# ---------------------------------------------------------------------------

@policies_bp.route('/api/policies/meta', methods=['GET'])
@login_required
def policy_meta():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT username FROM users ORDER BY username')
    users = [r['username'] for r in cur.fetchall()]
    cur.execute('SELECT name FROM files')
    exts = sorted({pe.file_extension(r['name']) for r in cur.fetchall() if pe.file_extension(r['name'])})
    conn.close()
    return jsonify({
        'users': users,
        'common_types': ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'jpg', 'jpeg', 'png',
                         'gif', 'zip', 'rar', '7z', 'mp3', 'mp4'],
        'existing_file_types': exts,
        'wildcard': pe.WILDCARD,
        'server_time': time.time(),
    })


# ---------------------------------------------------------------------------
# 策略列表 / 详情
# ---------------------------------------------------------------------------

@policies_bp.route('/api/policies', methods=['GET'])
@login_required
def list_policies():
    now = time.time()
    conn = get_db()
    policies = pe.list_policies(conn=conn)
    conflict_map = pe.current_conflicts(conn=conn)
    conn.close()
    return jsonify({
        'policies': [_serialize_with_conflicts(p, conflict_map, now) for p in policies],
        'active_count': sum(1 for p in policies if p.enabled),
        'enforced': any(p.enabled for p in policies),
        'server_time': now,
    })


@policies_bp.route('/api/policies/<policy_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
@login_required
def policy_detail(policy_id):
    actor = _current_user()

    if request.method == 'GET':
        conn = get_db()
        policy = pe.get_policy(policy_id, conn=conn)
        if not policy:
            conn.close()
            return jsonify({'error': '策略不存在'}), 404
        conflict_map = pe.current_conflicts(conn=conn)
        conn.close()
        return jsonify(_serialize_with_conflicts(policy, conflict_map, time.time()))

    if request.method == 'DELETE':
        conn = get_db()
        policy = pe.get_policy(policy_id, conn=conn)
        if not policy:
            conn.close()
            return jsonify({'error': '策略不存在'}), 404
        pe.delete_policy(policy_id, conn=conn)
        pe.log_event(
            'policy_config', 'info',
            policy_id=policy_id, policy_name=policy.name, actor=actor,
            source='policy_center', message=f'删除策略「{policy.name}」', conn=conn,
        )
        conn.close()
        return jsonify({'success': True, 'message': '策略已删除'})

    if request.method == 'PATCH':
        # 仅切换启停
        data = request.get_json(silent=True) or {}
        if 'enabled' not in data:
            return jsonify({'error': 'PATCH 仅支持 enabled 字段，请使用 PUT 提交完整策略',
                            'reason': 'validation_failed'}), 400
        enabled = bool(data.get('enabled'))
        conn = get_db()
        try:
            policy = pe.get_policy(policy_id, conn=conn)
            if not policy:
                conn.close()
                return jsonify({'error': '策略不存在'}), 404
            pe.set_enabled(policy_id, enabled, conn=conn)
            pe.log_event(
                'policy_config', 'info',
                policy_id=policy_id, policy_name=policy.name, actor=actor,
                source='policy_center',
                message=f'{"启用" if enabled else "停用"}策略「{policy.name}」',
                conn=conn,
            )
            conflict_map = pe.current_conflicts(conn=conn)
            policy = pe.get_policy(policy_id, conn=conn)
            serialized = _serialize_with_conflicts(policy, conflict_map, time.time())
        except pe.PolicyValidationError as exc:
            conn.close()
            return jsonify({'error': str(exc), 'reason': 'validation_failed'}), 400
        except pe.PolicyConflictError as exc:
            conn.close()
            return jsonify({'error': str(exc), 'reason': 'conflict', 'conflicts': exc.conflicts}), 409
        conn.close()
        return jsonify({'success': True, 'policy': serialized})

    # PUT：完整更新
    data = request.get_json(silent=True)
    try:
        payload = pe.prepare_policy_payload(data)
        enabled = bool(data['enabled']) if 'enabled' in data else None
        conn = get_db()
        try:
            policy = pe.update_policy(policy_id, payload, enabled=enabled, conn=conn)
            if not policy:
                conn.close()
                return jsonify({'error': '策略不存在'}), 404
            pe.log_event(
                'policy_config', 'info',
                policy_id=policy.id, policy_name=policy.name,
                actor=actor, source='policy_center',
                message=f'更新策略「{policy.name}」',
                detail={**payload, 'enabled': policy.enabled}, conn=conn,
            )
            conflict_map = pe.current_conflicts(conn=conn)
            serialized = _serialize_with_conflicts(policy, conflict_map, time.time())
        finally:
            conn.close()
    except pe.PolicyValidationError as exc:
        return jsonify({'error': str(exc), 'reason': 'validation_failed'}), 400
    except pe.PolicyConflictError as exc:
        return jsonify({'error': str(exc), 'reason': 'conflict', 'conflicts': exc.conflicts}), 409

    return jsonify({'success': True, 'policy': serialized})


# ---------------------------------------------------------------------------
# 新建 / 更新 / 启停 / 删除
# ---------------------------------------------------------------------------

@policies_bp.route('/api/policies', methods=['POST'])
@login_required
def create_policy():
    data = request.get_json(silent=True)
    actor = _current_user()
    try:
        payload = pe.prepare_policy_payload(data)
        enabled = bool(data.get('enabled', True))
        conn = get_db()
        try:
            policy = pe.create_policy(payload, actor, enabled=enabled, conn=conn)
            pe.log_event(
                'policy_config', 'info',
                policy_id=policy.id, policy_name=policy.name,
                actor=actor, source='policy_center',
                message=f'创建策略「{policy.name}」（{"启用" if enabled else "停用"}）',
                detail=payload, conn=conn,
            )
            conflict_map = pe.current_conflicts(conn=conn)
            serialized = _serialize_with_conflicts(policy, conflict_map, time.time())
        finally:
            conn.close()
    except pe.PolicyValidationError as exc:
        return jsonify({'error': str(exc), 'reason': 'validation_failed'}), 400
    except pe.PolicyConflictError as exc:
        return jsonify({'error': str(exc), 'reason': 'conflict', 'conflicts': exc.conflicts}), 409

    return jsonify({'success': True, 'policy': serialized}), 201


@policies_bp.route('/api/policies/<policy_id>/reset-usage', methods=['POST'])
@login_required
def reset_policy_usage(policy_id):
    actor = _current_user()
    conn = get_db()
    policy = pe.get_policy(policy_id, conn=conn)
    if not policy:
        conn.close()
        return jsonify({'error': '策略不存在'}), 404
    pe.reset_usage(policy_id, conn=conn)
    pe.log_event(
        'policy_config', 'info',
        policy_id=policy_id, policy_name=policy.name, actor=actor,
        source='policy_center', message=f'重置策略「{policy.name}」取件计数', conn=conn,
    )
    conn.close()
    return jsonify({'success': True, 'message': '取件计数已清零'})


# ---------------------------------------------------------------------------
# 命中结果预览（不落库、不扣次数）
# ---------------------------------------------------------------------------

@policies_bp.route('/api/policies/preview', methods=['POST'])
@login_required
def preview_policy():
    data = request.get_json(silent=True)
    try:
        # 预览也要先过一遍严格校验：空规则/非法时间不允许预览
        payload = pe.prepare_policy_payload(data)
    except pe.PolicyValidationError as exc:
        return jsonify({'error': str(exc), 'reason': 'validation_failed'}), 400

    scenarios = data.get('scenarios')
    if not scenarios:
        scenarios = pe.default_preview_scenarios(payload['users'], payload['file_types'],
                                                 sample_user=data.get('sample_user'),
                                                 sample_type=data.get('sample_type'))
    else:
        cleaned = []
        for sc in scenarios:
            if not isinstance(sc, dict) or not sc.get('username') or not sc.get('filename'):
                return jsonify({'error': '预览场景必须包含 username 与 filename',
                                'reason': 'validation_failed'}), 400
            cleaned.append(sc)
        scenarios = cleaned

    results = pe.preview_with_policy(payload, scenarios)
    description = payload['description'] or pe.build_description(
        pe._temp_policy(data.get('id') or pe.PREVIEW_USER, payload)
    )
    return jsonify({
        'policy': {**payload, 'description': description},
        'description': description,
        'results': results,
        'all_allowed': all(r['allowed'] for r in results),
    })


# ---------------------------------------------------------------------------
# 真实请求前的授权预检（结果与真正下载完全一致，但不扣次数、不写判定日志）
# ---------------------------------------------------------------------------

def _token_subject():
    """从请求解析令牌，返回 (username, error_payload, http_status)"""
    token = get_token_from_request()
    if not token:
        return None, {
            'allowed': False,
            'reason': pe.REASON_TOKEN_MISSING,
            'message': '未提供身份令牌，请先完成身份验证',
        }, 401
    username = get_username_from_token(token)
    if not username:
        return None, {
            'allowed': False,
            'reason': pe.REASON_TOKEN_INVALID,
            'message': '身份令牌无效或已过期，请重新登录后再试',
        }, 401
    return username, None, 200


@policies_bp.route('/api/policies/check/file/<file_id>', methods=['GET'])
def check_file(file_id):
    """目录页/重新进入页面：直连下载前预检"""
    username, err, status = _token_subject()
    if err:
        return jsonify(err), status

    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT id, name FROM files WHERE id = ?', (file_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'allowed': False, 'reason': pe.REASON_FILE_NOT_FOUND,
                        'message': '文件不存在'}), 404

    decision = pe.evaluate(username, row['name'], conn=conn)
    decision['subject'] = username
    decision['filename'] = row['name']
    decision['file_id'] = file_id
    decision['source'] = 'directory'
    conn.close()
    return jsonify(decision), 200


@policies_bp.route('/api/policies/check/share/<share_id>', methods=['GET'])
def check_share(share_id):
    """公开分享页：下载前预检。策略主体为分享创建者（令牌用于标识取件人）"""
    share = get_share_link_info(share_id)
    if not share:
        return jsonify({'allowed': False, 'reason': 'share_not_found',
                        'message': '分享链接不存在'}), 404

    valid, share_error = is_share_valid(share)
    if not valid:
        return jsonify({'allowed': False, 'reason': 'share_invalid',
                        'message': share_error}), 403

    requester = None
    token = get_token_from_request()
    if token:
        requester = get_username_from_token(token)  # 可能为 None（令牌过期的访客）

    conn = get_db()
    decision = pe.evaluate(share['created_by'], share['filename'], conn=conn)
    decision['subject'] = share['created_by']
    decision['requester'] = requester
    decision['filename'] = share['filename']
    decision['file_id'] = share['file_id']
    decision['source'] = 'public_share'
    conn.close()
    return jsonify(decision), 200


# ---------------------------------------------------------------------------
# 历史核对
# ---------------------------------------------------------------------------

@policies_bp.route('/api/policies/history', methods=['GET'])
@login_required
def policy_history():
    limit = request.args.get('limit', default=100, type=int)
    event_type = request.args.get('event_type') or None
    decision = request.args.get('decision') or None
    conn = get_db()
    logs = pe.list_logs(limit=limit, event_type=event_type, decision=decision, conn=conn)
    conn.close()
    return jsonify(logs)
