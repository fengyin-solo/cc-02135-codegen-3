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
from auth import verify_token, get_username_from_token, get_token_from_request, login_required
from policies import evaluate_download, public_decision
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

    if not token or not verify_token(token):
        # 失效令牌 / 无令牌：说明原因，绝不放行
        return jsonify({'error': '未授权或token已过期',
                        'decision': {'decision': 'deny', 'allowed': False,
                                     'reason': 'invalid_token',
                                     'reason_text': '未授权或token已过期',
                                     'reason_detail': '登录令牌缺失或已失效，请重新验证身份',
                                     'source': 'directory'}}), 401

    username = get_username_from_token(token)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name, path FROM files WHERE id = ?', (file_id,))
    file_info = cursor.fetchone()

    if not file_info:
        conn.close()
        return jsonify({'error': '文件不存在'}), 404

    if not os.path.abspath(file_info['path']).startswith(os.path.abspath(UPLOAD_FOLDER)):
        conn.close()
        return jsonify({'error': '非法文件路径'}), 403

    if not os.path.exists(file_info['path']):
        conn.close()
        return jsonify({'error': '文件不存在'}), 404

    # 统一授权判定（目录入口）：策略配置、判定、错误反馈、历史在此衔接
    decision = evaluate_download(
        username=username,
        file_id=file_id,
        filename=file_info['name'],
        source='directory',
        enforced=True,
        conn=conn,
    )
    conn.close()

    if decision['decision'] != 'allow':
        public = public_decision(decision)
        logger.info('下载被策略拒绝: user=%s file=%s reason=%s',
                    username, file_info['name'], decision['reason'])
        return jsonify({'error': f"{public['reason_text']}：{public['reason_detail']}",
                        'decision': public}), 403

    logger.info(f"文件下载: {file_info['name']} (ID: {file_id})")
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
    """获取分享链接信息（公开访问）

    - 无令牌（访客）：沿用分享链接自身的有效期/次数校验
    - 携带有效令牌（已登录用户，含“重新进入页面”）：改走统一策略引擎做预判，
      判定口径与目录下载完全一致；该预判不消耗取件次数
    """
    share = get_share_link_info(share_id)

    if not share:
        return jsonify({'error': '分享链接不存在'}), 404

    valid, error_msg = is_share_valid(share)

    token = get_token_from_request()
    username = get_username_from_token(token) if token else None

    decision_payload = None
    if username:
        # 已登录用户：与目录下载、公开页下载使用同一引擎（dry-run，仅展示）
        conn = get_db()
        decision = evaluate_download(
            username=username,
            file_id=share['file_id'],
            filename=share['filename'],
            source='share_reentry',
            enforced=False,
            conn=conn,
        )
        conn.close()
        decision_payload = public_decision(decision)
    else:
        # 访客：以分享链接自身有效性为准
        decision_payload = {
            'decision': 'allow' if valid else 'deny',
            'allowed': bool(valid),
            'reason': 'share_valid' if valid else 'share_invalid',
            'reason_text': '分享链接有效' if valid else (error_msg or '分享链接已失效'),
            'reason_detail': '' if valid else (error_msg or ''),
            'source': 'share_public',
            'used': None,
            'limit': None,
            'remaining': None,
            'policy': None,
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
        'authenticated': bool(username),
        'decision': decision_payload,
    }

    return jsonify(share_data)


def _serve_shared_file(share):
    """完成路径安全校验后发送文件"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name, path FROM files WHERE id = ?', (share['file_id'],))
    file_info = cursor.fetchone()
    conn.close()

    if not file_info:
        return jsonify({'error': '文件不存在'}), 404

    if not os.path.abspath(file_info['path']).startswith(os.path.abspath(UPLOAD_FOLDER)):
        return jsonify({'error': '非法文件路径'}), 403

    if not os.path.exists(file_info['path']):
        return jsonify({'error': '文件不存在'}), 404

    return file_info


@files_bp.route('/api/share/<share_id>/download', methods=['GET'])
def download_by_share(share_id):
    """通过分享链接下载（公开访问）

    - 无令牌访客：分享链接有效期/次数校验通过即放行（保持既有行为）
    - 已登录用户：统一走策略引擎，与从文件库目录发起的下载判定完全一致，
      且不再累加分享链接自身的下载次数（次数由策略的取件次数控制）
    """
    share = get_share_link_info(share_id)

    token = get_token_from_request()
    username = get_username_from_token(token) if token else None

    if username:
        # 已登录用户（含公开页/重新进入页）：统一策略判定
        if not share:
            return jsonify({'error': '分享链接不存在'}), 404

        file_info = _serve_shared_file(share)
        if isinstance(file_info, tuple):
            return file_info

        conn = get_db()
        decision = evaluate_download(
            username=username,
            file_id=share['file_id'],
            filename=file_info['name'],
            source='share_public',
            enforced=True,
            conn=conn,
        )
        conn.close()

        if decision['decision'] != 'allow':
            public = public_decision(decision)
            logger.info('分享下载被策略拒绝: user=%s share=%s reason=%s',
                        username, share_id, decision['reason'])
            return jsonify({'error': f"{public['reason_text']}：{public['reason_detail']}",
                            'decision': public}), 403

        logger.info(f"授权分享下载: 文件 {file_info['name']}, 分享ID {share_id}, 用户 {username}")
        return send_file(file_info['path'], as_attachment=True, download_name=file_info['name'])

    # 访客：沿用分享链接校验
    valid, error_msg = is_share_valid(share)
    if not valid:
        return jsonify({'error': error_msg}), 404

    file_info = _serve_shared_file(share)
    if isinstance(file_info, tuple):
        return file_info

    increment_download_count(share_id)

    logger.info(f"分享下载: 文件 {file_info['name']}, 分享ID {share_id}, 下载次数 {share['download_count'] + 1}")
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
