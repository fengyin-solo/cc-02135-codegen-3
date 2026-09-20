"""文件路由"""
import os
import re
import uuid
import time
import logging
from flask import request, jsonify, send_file
from werkzeug.utils import secure_filename
from routes import files_bp
from database import get_db
from auth import get_username_from_token, login_required
import policy_engine as pe
from config import UPLOAD_FOLDER, MAX_FILE_SIZE, BLOCKED_EXTENSIONS, SHARE_LINK_EXPIRE_HOURS, SHARE_LINK_MAX_DOWNLOADS

logger = logging.getLogger(__name__)


def allowed_file(filename):
    """检查文件扩展名是否被禁止"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext not in BLOCKED_EXTENSIONS


@files_bp.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': '没有文件'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '未选择文件'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': '不支持的文件类型'}), 400

    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)

    if file_size > MAX_FILE_SIZE:
        return jsonify({'error': f'文件大小超过限制（最大{MAX_FILE_SIZE // 1024 // 1024}MB）'}), 400

    file_id = str(uuid.uuid4())
    # 保留原始文件名用于显示（去掉路径分隔符防止注入）
    original_name = re.sub(r'[/\\]', '_', file.filename).strip()
    if not original_name:
        original_name = file_id

    # 磁盘上用 UUID + 扩展名存储，避免文件名编码问题
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    safe_filename = f"{file_id}.{ext}" if ext else file_id
    filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
    file.save(filepath)

    file_size = os.path.getsize(filepath)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO files (id, name, path, size) VALUES (?, ?, ?, ?)',
        (file_id, original_name, filepath, file_size)
    )
    conn.commit()
    conn.close()

    logger.info(f"文件上传成功: {original_name} (ID: {file_id}, 大小: {file_size} bytes)")
    return jsonify({'success': True, 'file_id': file_id, 'filename': original_name})


@files_bp.route('/api/files', methods=['GET'])
def list_files():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, path, size FROM files')
    files = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(files)


@files_bp.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    # 优先从 Authorization 头获取 token，兼容查询参数（已废弃）
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
    else:
        token = request.args.get('token')  # 向后兼容，建议前端迁移到 Authorization 头

    # 令牌层：缺失 / 失效都要解释原因，且绝不能放行
    if not token:
        pe.log_event('download_decision', 'deny', file_id=file_id, source='directory',
                     reason=pe.REASON_TOKEN_MISSING,
                     message='下载请求未携带身份令牌')
        return jsonify({'error': '未授权：请先完成身份验证',
                        'reason': pe.REASON_TOKEN_MISSING}), 401

    username = get_username_from_token(token)
    if not username:
        pe.log_event('download_decision', 'deny', file_id=file_id, source='directory',
                     reason=pe.REASON_TOKEN_INVALID,
                     message='下载请求携带的令牌无效或已过期')
        return jsonify({'error': '身份令牌无效或已过期，请重新登录后再试',
                        'reason': pe.REASON_TOKEN_INVALID}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, path FROM files WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()

    if not file_info:
        pe.log_event('download_decision', 'deny', subject=username, file_id=file_id,
                     source='directory', reason=pe.REASON_FILE_NOT_FOUND,
                     message='目标文件不存在', actor=username, conn=conn)
        conn.close()
        return jsonify({'error': '文件不存在', 'reason': pe.REASON_FILE_NOT_FOUND}), 404

    # 授权策略判定（与 /api/policies/check/file 使用同一个引擎，结果一致）
    decision = pe.evaluate(username, file_info['name'], conn=conn)
    if not decision['allowed']:
        pe.log_event(
            'download_decision', 'deny',
            policy_id=(decision.get('matched_policy') or {}).get('id'),
            subject=username, requester=username,
            file_id=file_id, filename=file_info['name'], source='directory',
            reason=decision['reason'], message=decision['message'],
            actor=username, conn=conn,
        )
        conn.close()
        logger.warning("下载被策略拒绝: 用户=%s 文件=%s 原因=%s",
                       username, file_info['name'], decision['reason'])
        return jsonify({'error': decision['message'], 'reason': decision['reason'],
                        'detail': {k: decision.get(k) for k in
                                   ('disabled_matches', 'conflicts', 'enforced')}}), 403

    if not os.path.abspath(file_info['path']).startswith(os.path.abspath(UPLOAD_FOLDER)):
        conn.close()
        return jsonify({'error': '非法文件路径'}), 403

    if not os.path.exists(file_info['path']):
        conn.close()
        return jsonify({'error': '文件不存在'}), 404

    if decision['matched_policy']:
        policy_id = decision['matched_policy']['id']
        policy_name = decision['matched_policy']['name']
        pe.increment_usage(policy_id, conn=conn)
    else:
        # 中心尚未配置策略：兼容放行，不扣任何配额
        policy_id, policy_name = None, None
    pe.log_event(
        'download_decision', 'allow',
        policy_id=policy_id, policy_name=policy_name,
        subject=username, requester=username,
        file_id=file_id, filename=file_info['name'], source='directory',
        reason=decision['reason'], message=decision['message'],
        actor=username, conn=conn,
    )
    conn.close()

    logger.info(f"文件下载: {file_info['name']} (ID: {file_id}, 命中策略: {policy_name or '未配置策略-兼容放行'})")
    return send_file(file_info['path'], as_attachment=True, download_name=file_info['name'])


def generate_short_id():
    """生成短的分享链接ID"""
    return uuid.uuid4().hex[:12]


def get_share_link_info(share_id):
    """获取分享链接信息，包含文件信息和有效性检查"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.id, s.file_id, s.created_by, s.expires_at, s.max_downloads, s.download_count, s.created_at,
               f.name as filename, f.size as filesize
        FROM share_links s
        JOIN files f ON s.file_id = f.id
        WHERE s.id = ?
    ''', (share_id,))
    share = cursor.fetchone()
    conn.close()
    return share


def is_share_valid(share):
    """检查分享链接是否有效"""
    if not share:
        return False, '分享链接不存在'

    if share['expires_at'] is not None and share['expires_at'] < time.time():
        return False, '分享链接已过期'

    if share['max_downloads'] is not None and share['download_count'] >= share['max_downloads']:
        return False, '分享链接下载次数已用完'

    return True, None


def increment_download_count(share_id):
    """增加下载次数"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE share_links SET download_count = download_count + 1 WHERE id = ?',
        (share_id,)
    )
    conn.commit()
    conn.close()


def get_token_from_request():
    """从请求中获取 token"""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return request.args.get('token')


@files_bp.route('/api/share', methods=['POST'])
@login_required
def create_share():
    """创建分享链接"""
    data = request.get_json()
    if not data:
        return jsonify({'error': '无效的请求数据'}), 400

    file_id = data.get('file_id', '').strip()
    expire_hours = data.get('expire_hours')
    max_downloads = data.get('max_downloads')

    if not file_id:
        return jsonify({'error': '文件ID不能为空'}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM files WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()

    if not file_info:
        conn.close()
        return jsonify({'error': '文件不存在'}), 404

    if expire_hours is None:
        expire_hours = SHARE_LINK_EXPIRE_HOURS

    if expire_hours < 0:
        expire_hours = None

    if expire_hours is not None:
        expires_at = time.time() + expire_hours * 3600
    else:
        expires_at = None

    if max_downloads is None:
        max_downloads = SHARE_LINK_MAX_DOWNLOADS

    if max_downloads < 0:
        max_downloads = None

    token = get_token_from_request()
    username = get_username_from_token(token)

    share_id = generate_short_id()

    cursor.execute('''
        INSERT INTO share_links (id, file_id, created_by, expires_at, max_downloads)
        VALUES (?, ?, ?, ?, ?)
    ''', (share_id, file_id, username, expires_at, max_downloads))

    conn.commit()
    conn.close()

    logger.info(f"分享链接创建成功: 文件 {file_info['name']}, 分享ID {share_id}, 创建者 {username}")

    return jsonify({
        'success': True,
        'share_id': share_id,
        'expires_at': expires_at,
        'max_downloads': max_downloads,
        'filename': file_info['name']
    })


@files_bp.route('/api/share/<share_id>', methods=['GET'])
def get_share(share_id):
    """获取分享链接信息（公开访问），同时返回授权策略预判，保证刷新/重新进入结果一致"""
    share = get_share_link_info(share_id)
    valid, error_msg = is_share_valid(share)

    if not share:
        return jsonify({'error': '分享链接不存在'}), 404

    # 策略判定：以分享创建者为主体（与真正点下载时的判定完全相同，但不扣次数）
    policy_decision = None
    if valid:
        conn = get_db()
        policy_decision = pe.evaluate(share['created_by'], share['filename'], conn=conn)
        conn.close()
        # 前端只需展示层字段
        policy_decision = {
            'allowed': policy_decision['allowed'],
            'reason': policy_decision['reason'],
            'message': policy_decision['message'],
            'matched_policy': policy_decision.get('matched_policy'),
            'enforced': policy_decision.get('enforced'),
            'disabled_matches': policy_decision.get('disabled_matches', []),
        }

    share_data = {
        'share_id': share['id'],
        'filename': share['filename'],
        'filesize': share['filesize'],
        'created_by': share['created_by'],
        'expires_at': share['expires_at'],
        'max_downloads': share['max_downloads'],
        'download_count': share['download_count'],
        'created_at': share['created_at'],
        'is_valid': valid,
        'error_msg': error_msg,
        'policy': policy_decision,
    }

    return jsonify(share_data)


@files_bp.route('/api/share/<share_id>/download', methods=['GET'])
def download_by_share(share_id):
    """通过分享链接下载文件（公开访问）

    授权判定主体是分享创建者：创建者授予自己哪些 用户×类型×时间×次数 的范围，
    其分享链接就在同一范围内可用。判定引擎与目录页直连下载完全一致，
    因此从公开页、目录页、重新进入的页面发起请求结果相同。
    """
    share = get_share_link_info(share_id)
    valid, error_msg = is_share_valid(share)

    if not valid:
        return jsonify({'error': error_msg}), 404

    # 取件人可能携带（过期）令牌，仅用于历史核对，不影响授权结果
    requester = None
    token = get_token_from_request()
    if token:
        requester = get_username_from_token(token)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name, path FROM files WHERE id = ?', (share['file_id'],))
    file_info = cursor.fetchone()

    if not file_info:
        conn.close()
        return jsonify({'error': '文件不存在'}), 404

    decision = pe.evaluate(share['created_by'], file_info['name'], conn=conn)
    if not decision['allowed']:
        pe.log_event(
            'download_decision', 'deny',
            policy_id=(decision.get('matched_policy') or {}).get('id'),
            subject=share['created_by'], requester=requester,
            file_id=share['file_id'], filename=file_info['name'],
            source='public_share', reason=decision['reason'],
            message=decision['message'], conn=conn,
        )
        conn.close()
        logger.warning("分享下载被策略拒绝: 分享=%s 主体=%s 取件人=%s 原因=%s",
                       share_id, share['created_by'], requester, decision['reason'])
        return jsonify({'error': decision['message'], 'reason': decision['reason'],
                        'detail': {k: decision.get(k) for k in
                                   ('disabled_matches', 'conflicts', 'enforced')}}), 403

    if not os.path.abspath(file_info['path']).startswith(os.path.abspath(UPLOAD_FOLDER)):
        conn.close()
        return jsonify({'error': '非法文件路径'}), 403

    if not os.path.exists(file_info['path']):
        conn.close()
        return jsonify({'error': '文件不存在'}), 404

    if decision['matched_policy']:
        policy_id = decision['matched_policy']['id']
        policy_name = decision['matched_policy']['name']
        pe.increment_usage(policy_id, conn=conn)
    else:
        # 中心尚未配置策略：兼容放行，不扣任何配额
        policy_id, policy_name = None, None
    increment_download_count(share_id)
    pe.log_event(
        'download_decision', 'allow',
        policy_id=policy_id, policy_name=policy_name,
        subject=share['created_by'], requester=requester,
        file_id=share['file_id'], filename=file_info['name'],
        source='public_share', reason=decision['reason'],
        message=decision['message'], conn=conn,
    )
    conn.close()

    logger.info(f"分享下载: 文件 {file_info['name']}, 分享ID {share_id}, "
                f"命中策略 {policy_name or '未配置策略-兼容放行'}, 下载次数 {share['download_count'] + 1}")
    return send_file(file_info['path'], as_attachment=True, download_name=file_info['name'])


@files_bp.route('/api/shares', methods=['GET'])
@login_required
def list_shares():
    """获取当前用户的所有分享链接"""
    token = get_token_from_request()
    username = get_username_from_token(token)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.id, s.file_id, s.created_by, s.expires_at, s.max_downloads, s.download_count, s.created_at,
               f.name as filename, f.size as filesize
        FROM share_links s
        JOIN files f ON s.file_id = f.id
        WHERE s.created_by = ?
        ORDER BY s.created_at DESC
    ''', (username,))
    shares = cursor.fetchall()
    conn.close()

    result = []
    for share in shares:
        valid, error_msg = is_share_valid(share)
        result.append({
            'share_id': share['id'],
            'file_id': share['file_id'],
            'filename': share['filename'],
            'filesize': share['filesize'],
            'expires_at': share['expires_at'],
            'max_downloads': share['max_downloads'],
            'download_count': share['download_count'],
            'created_at': share['created_at'],
            'is_valid': valid,
            'error_msg': error_msg
        })

    return jsonify(result)


@files_bp.route('/api/share/<share_id>', methods=['DELETE'])
@login_required
def delete_share(share_id):
    """删除分享链接"""
    token = get_token_from_request()
    username = get_username_from_token(token)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT created_by, file_id FROM share_links WHERE id = ?', (share_id,))
    share = cursor.fetchone()

    if not share:
        conn.close()
        return jsonify({'error': '分享链接不存在'}), 404

    if share['created_by'] != username:
        conn.close()
        return jsonify({'error': '无权限删除此分享链接'}), 403

    cursor.execute('DELETE FROM share_links WHERE id = ?', (share_id,))
    conn.commit()
    conn.close()

    logger.info(f"分享链接删除: 分享ID {share_id}, 文件ID {share['file_id']}, 操作者 {username}")
    return jsonify({'success': True, 'message': '分享链接已删除'})
