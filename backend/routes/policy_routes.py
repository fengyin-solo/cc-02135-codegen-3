"""下载授权策略中心路由：策略配置、启停、冲突提示、结果预览、历史核对"""
import logging
from functools import wraps

from flask import request, jsonify

from routes import policy_bp
from database import get_db
from auth import get_token_from_request, get_username_from_token
from config import ADMIN_USERNAMES
from policies import (
    row_to_policy, describe_policy, validate_policy_payload, find_overlaps,
    evaluate_download, public_decision, get_all_policies, parse_hhmm,
)

logger = logging.getLogger(__name__)


def admin_required(f):
    """策略中心仅管理员可用；同时校验登录态"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        username = get_username_from_token(token) if token else None
        if not username:
            return jsonify({'error': '未授权或token已过期'}), 401
        if username not in ADMIN_USERNAMES:
            logger.warning('非管理员访问策略中心: %s', username)
            return jsonify({'error': '仅管理员可管理下载授权策略'}), 403
        request.admin_username = username
        return f(*args, **kwargs)
    return decorated


def _serialize_policy(row, description_text=None):
    data = row_to_policy(row)
    data['description_text'] = description_text or describe_policy(data)
    return data


@policy_bp.route('/api/policies', methods=['GET'])
@admin_required
def list_policies():
    """列出全部策略（含说明与当前状态）"""
    conn = get_db()
    rows = get_all_policies(conn)
    result = [_serialize_policy(row) for row in rows]
    conn.close()
    return jsonify(result)


@policy_bp.route('/api/policies', methods=['POST'])
@admin_required
def create_policy():
    """新增策略：空规则硬拒绝；重叠规则作为冲突警告返回但允许保存"""
    data = request.get_json(silent=True)
    conn = get_db()
    clean, errors = validate_policy_payload(data, conn)
    if errors:
        conn.close()
        return jsonify({'error': '策略校验未通过', 'errors': errors}), 400

    warnings = []
    overlaps = find_overlaps(clean, conn)
    if overlaps:
        warnings.append(
            '与以下启用策略的授权范围重叠，同一请求若同时命中将被判为冲突而拒绝：' +
            '、'.join(f'「{o["name"]}」{o["quota_note"]}' for o in overlaps)
        )

    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO download_policies
            (name, description, usernames, extensions,
             start_time, end_time, max_downloads, enabled, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
    ''', (
        clean['name'], clean['description'],
        ','.join(clean['usernames']), ','.join(clean['extensions']),
        clean['start_min'], clean['end_min'], clean['max_downloads'],
        request.admin_username,
    ))
    conn.commit()
    policy_id = cursor.lastrowid
    cursor.execute('SELECT * FROM download_policies WHERE id = ?', (policy_id,))
    policy = _serialize_policy(dict(cursor.fetchone()))
    conn.close()

    logger.info('策略创建成功: id=%s name=%s by=%s', policy_id, clean['name'], request.admin_username)
    return jsonify({'success': True, 'policy': policy, 'warnings': warnings}), 201


@policy_bp.route('/api/policies/<int:policy_id>', methods=['GET'])
@admin_required
def get_policy(policy_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM download_policies WHERE id = ?', (policy_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({'error': '策略不存在'}), 404
    return jsonify(_serialize_policy(dict(row)))


@policy_bp.route('/api/policies/<int:policy_id>', methods=['PUT'])
@admin_required
def update_policy(policy_id):
    """编辑策略：空规则拒绝；重叠给出冲突提示"""
    data = request.get_json(silent=True)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM download_policies WHERE id = ?', (policy_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': '策略不存在'}), 404

    clean, errors = validate_policy_payload(data, conn)
    if errors:
        conn.close()
        return jsonify({'error': '策略校验未通过', 'errors': errors}), 400

    warnings = []
    overlaps = find_overlaps(clean, conn, exclude_id=policy_id)
    if overlaps:
        warnings.append(
            '与以下启用策略的授权范围重叠，同一请求若同时命中将被判为冲突而拒绝：' +
            '、'.join(f'「{o["name"]}」{o["quota_note"]}' for o in overlaps)
        )

    enabled = 1 if data.get('enabled', True) else 0
    cursor.execute('''
        UPDATE download_policies SET
            name = ?, description = ?, usernames = ?, extensions = ?,
            start_time = ?, end_time = ?, max_downloads = ?, enabled = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (
        clean['name'], clean['description'],
        ','.join(clean['usernames']), ','.join(clean['extensions']),
        clean['start_min'], clean['end_min'], clean['max_downloads'],
        enabled, policy_id,
    ))
    conn.commit()
    cursor.execute('SELECT * FROM download_policies WHERE id = ?', (policy_id,))
    policy = _serialize_policy(dict(cursor.fetchone()))
    conn.close()

    logger.info('策略更新: id=%s by=%s', policy_id, request.admin_username)
    return jsonify({'success': True, 'policy': policy, 'warnings': warnings})


@policy_bp.route('/api/policies/<int:policy_id>/toggle', methods=['POST'])
@admin_required
def toggle_policy(policy_id):
    """启用 / 停用策略，返回停用后可能暴露的问题提示"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM download_policies WHERE id = ?', (policy_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': '策略不存在'}), 404

    new_enabled = 0 if row['enabled'] else 1
    cursor.execute(
        'UPDATE download_policies SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        (new_enabled, policy_id)
    )
    conn.commit()
    cursor.execute('SELECT * FROM download_policies WHERE id = ?', (policy_id,))
    policy = _serialize_policy(dict(cursor.fetchone()))

    warnings = []
    if new_enabled == 0:
        warnings.append(
            f'策略「{policy["name"]}」已停用：仅被该策略覆盖的下载请求将因“匹配策略已停用”被拒绝，不会放行'
        )
    else:
        clean_like = {
            'usernames': [u.lower() for u in policy['usernames']],
            'extensions': [e.lstrip('.').lower() for e in policy['extensions']],
            'start_min': parse_hhmm(policy['start_time']),
            'end_min': parse_hhmm(policy['end_time']),
            'max_downloads': policy['max_downloads'],
        }
        overlaps = find_overlaps(clean_like, conn, exclude_id=policy_id)
        if overlaps:
            warnings.append(
                '启用后与以下策略重叠，同时命中会判为冲突：' +
                '、'.join(f'「{o["name"]}」' for o in overlaps)
            )
    conn.close()

    return jsonify({'success': True, 'policy': policy, 'warnings': warnings})


@policy_bp.route('/api/policies/<int:policy_id>', methods=['DELETE'])
@admin_required
def delete_policy(policy_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM download_policies WHERE id = ?', (policy_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': '策略不存在'}), 404
    cursor.execute('DELETE FROM download_policies WHERE id = ?', (policy_id,))
    conn.commit()
    conn.close()
    logger.info('策略删除: id=%s name=%s by=%s', policy_id, row['name'], request.admin_username)
    return jsonify({'success': True, 'message': f'策略「{row["name"]}」已删除'})


@policy_bp.route('/api/policies/preview', methods=['POST'])
@admin_required
def preview_decision():
    """策略命中结果预览：不落历史、不消耗取件次数"""
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    filename = str(data.get('filename', '')).strip()
    source = str(data.get('source', 'directory')).strip() or 'directory'

    errors = []
    if not username:
        errors.append('预览需要指定用户名')
    if not filename:
        errors.append('预览需要指定文件名（用于判定文件类型）')
    if source not in ('directory', 'share_public', 'share_reentry'):
        errors.append('来源取值不合法')
    if errors:
        return jsonify({'error': '预览参数不完整', 'errors': errors}), 400

    conn = get_db()
    # 校验用户真实存在，避免预览给出误导性结论
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM users WHERE LOWER(username) = ?', (username.lower(),))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': '预览参数不完整',
                        'errors': [f'用户「{username}」不存在']}), 400

    result = evaluate_download(
        username=username,
        file_id=data.get('file_id') or 'preview',
        filename=filename,
        source=source,
        enforced=False,
        conn=conn,
    )
    conn.close()
    return jsonify({'success': True, 'decision': public_decision(result)})


@policy_bp.route('/api/policies/decision-logs', methods=['GET'])
@admin_required
def list_decision_logs():
    """历史核对：支持按用户、文件、结论、来源过滤与分页"""
    username = request.args.get('username', '').strip()
    filename = request.args.get('filename', '').strip()
    decision = request.args.get('decision', '').strip()
    source = request.args.get('source', '').strip()

    try:
        page = max(1, int(request.args.get('page', 1)))
        page_size = min(100, max(1, int(request.args.get('page_size', 20))))
    except ValueError:
        page, page_size = 1, 20

    where, params = [], []
    if username:
        where.append('username LIKE ?')
        params.append(f'%{username}%')
    if filename:
        where.append('filename LIKE ?')
        params.append(f'%{filename}%')
    if decision in ('allow', 'deny'):
        where.append('decision = ?')
        params.append(decision)
    if source:
        where.append('source = ?')
        params.append(source)
    where_sql = (' WHERE ' + ' AND '.join(where)) if where else ''

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f'SELECT COUNT(*) AS cnt FROM policy_decision_log{where_sql}', params)
    total = cursor.fetchone()['cnt']

    cursor.execute(
        f'''SELECT * FROM policy_decision_log{where_sql}
            ORDER BY id DESC LIMIT ? OFFSET ?''',
        params + [page_size, (page - 1) * page_size]
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        'total': total,
        'page': page,
        'page_size': page_size,
        'items': rows,
    })
