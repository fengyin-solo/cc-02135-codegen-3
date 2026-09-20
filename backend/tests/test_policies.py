"""下载授权策略中心测试

覆盖：
- 配置层：空规则/非法时间/次数为 0 拒绝保存；冲突检测与 409；启停
- 判定层：用户×类型×时间×次数；停用不放行；令牌失效拒绝；无策略兼容
- 一致性：目录页直连下载、公开分享页下载、重新进入（预检）结果一致
- 展示层：策略说明、命中预览、历史核对
"""
import io
import json
import time

import pytest

import policy_engine as pe
from database import get_db


@pytest.fixture(autouse=True)
def clean_policies():
    """每个用例独立：清空策略与日志，避免影响其它模块的“无策略兼容”语义"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM download_policies')
    cur.execute('DELETE FROM policy_logs')
    conn.commit()
    conn.close()
    yield
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM download_policies')
    cur.execute('DELETE FROM policy_logs')
    conn.commit()
    conn.close()


def _auth(client, username='admin', password='admin123'):
    from auth import rate_limit_store
    rate_limit_store.clear()
    resp = client.post('/api/auth', json={'username': username, 'password': password})
    return resp.get_json()['token']


def _upload(client, name='report.pdf', content=b'pdf-bytes'):
    resp = client.post('/api/upload',
                       data={'file': (io.BytesIO(content), name)},
                       content_type='multipart/form-data')
    return resp.get_json()['file_id']


def _make_policy(client, token, **overrides):
    payload = {
        'name': '测试策略',
        'users': ['admin'],
        'file_types': ['pdf'],
        'start_at': None,
        'end_at': None,
        'max_downloads': 5,
        'enabled': True,
    }
    payload.update(overrides)
    return client.post('/api/policies', json=payload,
                       headers={'Authorization': f'Bearer {token}'})


# --------------------------------------------------------------------------
# 配置层：校验
# --------------------------------------------------------------------------

def test_empty_users_rejected(client, auth_token):
    resp = _make_policy(client, auth_token, users=[])
    assert resp.status_code == 400
    assert '不能为空' in resp.get_json()['error']


def test_empty_file_types_rejected(client, auth_token):
    resp = _make_policy(client, auth_token, file_types=[])
    assert resp.status_code == 400
    assert '不能为空' in resp.get_json()['error']


def test_blank_entries_rejected(client, auth_token):
    resp = _make_policy(client, auth_token, users=['   '])
    assert resp.status_code == 400


def test_empty_name_rejected(client, auth_token):
    resp = _make_policy(client, auth_token, name='   ')
    assert resp.status_code == 400


def test_zero_max_downloads_rejected(client, auth_token):
    resp = _make_policy(client, auth_token, max_downloads=0)
    assert resp.status_code == 400
    assert '不能为 0' in resp.get_json()['error']


def test_end_before_start_rejected(client, auth_token):
    now = time.time()
    resp = _make_policy(client, auth_token, start_at=now + 3600, end_at=now)
    assert resp.status_code == 400
    assert '结束时间必须晚于开始时间' in resp.get_json()['error']


def test_end_already_passed_rejected(client, auth_token):
    resp = _make_policy(client, auth_token, end_at=time.time() - 10)
    assert resp.status_code == 400
    assert '已过' in resp.get_json()['error']


def test_duplicate_entries_rejected(client, auth_token):
    resp = _make_policy(client, auth_token, file_types=['pdf', 'PDF'])
    assert resp.status_code == 400


def test_unlimited_downloads_minus_one(client, auth_token):
    resp = _make_policy(client, auth_token, max_downloads=-1)
    assert resp.status_code == 201
    assert resp.get_json()['policy']['max_downloads'] is None


def test_policy_requires_auth(client):
    assert client.get('/api/policies').status_code == 401
    assert client.post('/api/policies', json={}).status_code == 401
    assert client.get('/api/policies/history').status_code == 401


# --------------------------------------------------------------------------
# 配置层：冲突提示
# --------------------------------------------------------------------------

def test_overlapping_policies_conflict(client, auth_token):
    r1 = _make_policy(client, auth_token, name='策略A', users=['admin'], file_types=['pdf'])
    assert r1.status_code == 201
    r2 = _make_policy(client, auth_token, name='策略B', users=['admin', 'user'],
                      file_types=['pdf', 'txt'])
    assert r2.status_code == 409
    body = r2.get_json()
    assert body['reason'] == 'conflict'
    assert body['conflicts'][0]['policy_name'] == '策略A'
    assert set(body['conflicts'][0]['dimensions']) == {'用户', '文件类型', '时间范围'}


def test_non_overlapping_type_ok(client, auth_token):
    _make_policy(client, auth_token, name='策略A', users=['admin'], file_types=['pdf'])
    r2 = _make_policy(client, auth_token, name='策略B', users=['admin'], file_types=['txt'])
    assert r2.status_code == 201


def test_disabled_policy_does_not_conflict(client, auth_token):
    _make_policy(client, auth_token, name='策略A', enabled=False)
    r2 = _make_policy(client, auth_token, name='策略B')
    assert r2.status_code == 201


def test_enable_conflicts_returns_409(client, auth_token):
    a = _make_policy(client, auth_token, name='A').get_json()['policy']
    b = _make_policy(client, auth_token, name='B', file_types=['txt'], enabled=True).get_json()['policy']
    # 把 B 改成与 A 重叠但保持停用，再启用应报冲突
    resp = client.put(f"/api/policies/{b['id']}",
                      json={'name': 'B', 'users': ['admin'], 'file_types': ['pdf'],
                            'max_downloads': 5, 'enabled': False},
                      headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 200
    resp = client.patch(f"/api/policies/{b['id']}", json={'enabled': True},
                        headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 409


def test_time_disjoint_no_conflict(client, auth_token):
    now = time.time()
    _make_policy(client, auth_token, name='A', start_at=now, end_at=now + 100)
    r = _make_policy(client, auth_token, name='B', start_at=now + 200, end_at=now + 300)
    assert r.status_code == 201


def test_list_flags_conflicts(client, auth_token):
    # 构造存量冲突：先建一条停用重叠策略，启用后列表应标注冲突
    _make_policy(client, auth_token, name='A')
    b = _make_policy(client, auth_token, name='B', enabled=False).get_json()['policy']
    client.patch(f"/api/policies/{b['id']}", json={'enabled': True},
                 headers={'Authorization': f'Bearer {auth_token}'})  # 会被 409 拒绝
    # 直接改库模拟历史遗留冲突
    conn = get_db()
    conn.execute('UPDATE download_policies SET enabled = 1 WHERE id = ?', (b['id'],))
    conn.commit()
    conn.close()
    resp = client.get('/api/policies', headers={'Authorization': f'Bearer {auth_token}'})
    policies = resp.get_json()['policies']
    flagged = [p for p in policies if p['conflicts']]
    assert len(flagged) == 2


# --------------------------------------------------------------------------
# 启停
# --------------------------------------------------------------------------

def test_disable_blocks_download(client, auth_token):
    policy = _make_policy(client, auth_token).get_json()['policy']
    file_id = _upload(client)
    assert client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {auth_token}'}).status_code == 200

    client.patch(f"/api/policies/{policy['id']}", json={'enabled': False},
                 headers={'Authorization': f'Bearer {auth_token}'})
    resp = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 403
    body = resp.get_json()
    assert body['reason'] == pe.REASON_POLICY_DISABLED
    assert '已停用' in body['error']


def test_enable_expired_policy_rejected(client, auth_token):
    policy = _make_policy(client, auth_token, end_at=time.time() + 3600).get_json()['policy']
    conn = get_db()
    conn.execute('UPDATE download_policies SET enabled = 0, end_at = ? WHERE id = ?',
                 (time.time() - 10, policy['id']))
    conn.commit()
    conn.close()
    resp = client.patch(f"/api/policies/{policy['id']}", json={'enabled': True},
                        headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 400
    assert '时间窗口已结束' in resp.get_json()['error']


# --------------------------------------------------------------------------
# 判定层：直连下载
# --------------------------------------------------------------------------

def test_matching_policy_allows(client, auth_token):
    _make_policy(client, auth_token)
    file_id = _upload(client, 'ok.pdf')
    resp = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 200
    assert resp.data == b'pdf-bytes'


def test_unauthorized_user_denied(client, auth_token):
    _make_policy(client, auth_token, users=['admin'])
    user_token = _auth(client, 'user', 'user123')
    file_id = _upload(client)
    resp = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {user_token}'})
    assert resp.status_code == 403
    assert resp.get_json()['reason'] == pe.REASON_USER_FORBIDDEN


def test_unauthorized_type_denied(client, auth_token):
    _make_policy(client, auth_token, file_types=['pdf'])
    file_id = _upload(client, 'movie.mp4', b'x')
    resp = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 403
    assert resp.get_json()['reason'] == pe.REASON_TYPE_FORBIDDEN


def test_wildcard_user_and_type(client, auth_token):
    _make_policy(client, auth_token, users=['*'], file_types=['*'])
    user_token = _auth(client, 'test', 'test123')
    file_id = _upload(client, 'anything.xyz', b'x')
    resp = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {user_token}'})
    assert resp.status_code == 200


def test_time_window_before_start_denied(client, auth_token):
    now = time.time()
    _make_policy(client, auth_token, start_at=now + 3600, end_at=now + 7200)
    file_id = _upload(client)
    resp = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 403
    assert resp.get_json()['reason'] == pe.REASON_OUTSIDE_WINDOW


def test_quota_exhausted_denied(client, auth_token):
    _make_policy(client, auth_token, max_downloads=1)
    file_id = _upload(client)
    headers = {'Authorization': f'Bearer {auth_token}'}
    assert client.get(f'/api/download/{file_id}', headers=headers).status_code == 200
    resp = client.get(f'/api/download/{file_id}', headers=headers)
    assert resp.status_code == 403
    assert resp.get_json()['reason'] == pe.REASON_QUOTA_EXHAUSTED
    assert '取件次数已用完' in resp.get_json()['error']


def test_quota_counts_only_real_downloads(client, auth_token):
    policy = _make_policy(client, auth_token, max_downloads=1).get_json()['policy']
    file_id = _upload(client)
    # 预检不扣次数
    for _ in range(3):
        pre = client.get(f'/api/policies/check/file/{file_id}',
                         headers={'Authorization': f'Bearer {auth_token}'})
        assert pre.get_json()['allowed'] is True
    detail = client.get(f"/api/policies/{policy['id']}",
                        headers={'Authorization': f'Bearer {auth_token}'}).get_json()
    assert detail['used_downloads'] == 0
    # 真正下载后才扣
    client.get(f'/api/download/{file_id}',
               headers={'Authorization': f'Bearer {auth_token}'})
    detail = client.get(f"/api/policies/{policy['id']}",
                        headers={'Authorization': f'Bearer {auth_token}'}).get_json()
    assert detail['used_downloads'] == 1


def test_reset_usage(client, auth_token):
    policy = _make_policy(client, auth_token, max_downloads=1).get_json()['policy']
    file_id = _upload(client)
    client.get(f'/api/download/{file_id}', headers={'Authorization': f'Bearer {auth_token}'})
    resp = client.post(f"/api/policies/{policy['id']}/reset-usage",
                       headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 200
    assert client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {auth_token}'}).status_code == 200


def test_missing_token_explained(client):
    _make_policy(client, _auth(client))
    file_id = _upload(client)
    resp = client.get(f'/api/download/{file_id}')
    assert resp.status_code == 401
    assert resp.get_json()['reason'] == pe.REASON_TOKEN_MISSING


def test_invalid_token_explained(client, auth_token):
    _make_policy(client, auth_token)
    file_id = _upload(client)
    resp = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': 'Bearer not-a-real-token'})
    assert resp.status_code == 401
    assert resp.get_json()['reason'] == pe.REASON_TOKEN_INVALID
    assert '过期' in resp.get_json()['error']


def test_expired_token_denied(client, auth_token, db_conn):
    _make_policy(client, auth_token)
    file_id = _upload(client)
    cur = db_conn.cursor()
    cur.execute('UPDATE tokens SET expires_at = ? WHERE token = ?', (time.time() - 1, auth_token))
    db_conn.commit()
    resp = client.get(f'/api/download/{file_id}?token={auth_token}')
    assert resp.status_code == 401
    assert resp.get_json()['reason'] == pe.REASON_TOKEN_INVALID


def test_runtime_conflict_denied(client, auth_token, db_conn):
    """绕过保存期校验，模拟历史遗留冲突：引擎在运行时必须拒绝"""
    a = _make_policy(client, auth_token, name='A').get_json()['policy']
    b = _make_policy(client, auth_token, name='B', enabled=False).get_json()['policy']
    cur = db_conn.cursor()
    cur.execute("UPDATE download_policies SET enabled = 1, users_json = ?, file_types_json = ? WHERE id = ?",
                (json.dumps(['admin']), json.dumps(['pdf']), b['id']))
    db_conn.commit()
    file_id = _upload(client)
    resp = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 403
    assert resp.get_json()['reason'] == pe.REASON_CONFLICT


def test_no_policy_compat_mode_allows(client, auth_token):
    """从未配置策略时，合法登录请求不能被误伤"""
    file_id = _upload(client)
    resp = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 200


def test_delete_policy_then_other_still_enforces(client, auth_token):
    a = _make_policy(client, auth_token, name='A', file_types=['pdf']).get_json()['policy']
    b = _make_policy(client, auth_token, name='B', file_types=['txt']).get_json()['policy']
    client.delete(f"/api/policies/{a['id']}", headers={'Authorization': f'Bearer {auth_token}'})
    # pdf 不再授权
    pdf_id = _upload(client, 'a.pdf')
    resp = client.get(f'/api/download/{pdf_id}',
                      headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 403
    # txt 仍然放行
    txt_id = _upload(client, 'b.txt', b'x')
    assert client.get(f'/api/download/{txt_id}',
                      headers={'Authorization': f'Bearer {auth_token}'}).status_code == 200


# --------------------------------------------------------------------------
# 一致性：目录 / 公开页 / 重新进入
# --------------------------------------------------------------------------

def test_directory_check_matches_actual_download(client, auth_token):
    _make_policy(client, auth_token)
    file_id = _upload(client)
    pre = client.get(f'/api/policies/check/file/{file_id}',
                     headers={'Authorization': f'Bearer {auth_token}'})
    assert pre.status_code == 200
    assert pre.get_json()['allowed'] is True
    assert pre.get_json()['reason'] == 'allowed'

    # 范围外用户预检与真实下载结论一致
    user_token = _auth(client, 'user', 'user123')
    pre_user = client.get(f'/api/policies/check/file/{file_id}',
                          headers={'Authorization': f'Bearer {user_token}'})
    assert pre_user.get_json()['allowed'] is False
    assert pre_user.get_json()['reason'] == pe.REASON_USER_FORBIDDEN
    real = client.get(f'/api/download/{file_id}',
                      headers={'Authorization': f'Bearer {user_token}'})
    assert real.status_code == 403
    assert real.get_json()['reason'] == pe.REASON_USER_FORBIDDEN


def test_share_page_consistent_with_directory(client, auth_token):
    """分享下载以创建者为策略主体：预检、GET 分享信息、真实下载三处结论一致"""
    _make_policy(client, auth_token, users=['admin'], file_types=['pdf'], max_downloads=5)
    file_id = _upload(client, 'deck.pdf')
    share_id = client.post('/api/share', json={'file_id': file_id, 'expire_hours': 24,
                                               'max_downloads': 5},
                           headers={'Authorization': f'Bearer {auth_token}'}).get_json()['share_id']

    # 公开 GET 信息里的预判
    info = client.get(f'/api/share/{share_id}').get_json()
    assert info['policy']['allowed'] is True

    # 公开预检（无令牌访客）
    pre = client.get(f'/api/policies/check/share/{share_id}')
    assert pre.status_code == 200
    assert pre.get_json()['allowed'] is True

    # 真实公开下载
    assert client.get(f'/api/share/{share_id}/download').status_code == 200

    # 策略不允许的类型：三处都拒绝
    other = _upload(client, 'clip.mp4', b'v')
    bad_share = client.post('/api/share', json={'file_id': other, 'expire_hours': 24,
                                                'max_downloads': 5},
                            headers={'Authorization': f'Bearer {auth_token}'}).get_json()['share_id']
    info_bad = client.get(f'/api/share/{bad_share}').get_json()
    assert info_bad['policy']['allowed'] is False
    assert info_bad['policy']['reason'] == pe.REASON_TYPE_FORBIDDEN
    assert client.get(f'/api/policies/check/share/{bad_share}').get_json()['allowed'] is False
    resp = client.get(f'/api/share/{bad_share}/download')
    assert resp.status_code == 403
    assert resp.get_json()['reason'] == pe.REASON_TYPE_FORBIDDEN


def test_share_download_denied_when_policy_disabled(client, auth_token):
    policy = _make_policy(client, auth_token).get_json()['policy']
    file_id = _upload(client)
    share_id = client.post('/api/share', json={'file_id': file_id},
                           headers={'Authorization': f'Bearer {auth_token}'}).get_json()['share_id']
    assert client.get(f'/api/share/{share_id}/download').status_code == 200
    client.patch(f"/api/policies/{policy['id']}", json={'enabled': False},
                 headers={'Authorization': f'Bearer {auth_token}'})
    # 重新进入公开页
    info = client.get(f'/api/share/{share_id}').get_json()
    assert info['is_valid'] is True  # 分享本身有效
    assert info['policy']['allowed'] is False
    assert info['policy']['reason'] == pe.REASON_POLICY_DISABLED
    resp = client.get(f'/api/share/{share_id}/download')
    assert resp.status_code == 403
    assert '已停用' in resp.get_json()['error']


def test_share_check_invalid_share(client):
    assert client.get('/api/policies/check/share/nope').status_code == 404


def test_repeated_reentry_same_decision(client, auth_token):
    """重新进入页面多次（含真实下载后次数变化），判定始终来自同一引擎"""
    _make_policy(client, auth_token, max_downloads=2)
    file_id = _upload(client)
    share_id = client.post('/api/share', json={'file_id': file_id, 'max_downloads': 10},
                           headers={'Authorization': f'Bearer {auth_token}'}).get_json()['share_id']

    results = []
    for i in range(3):
        info = client.get(f'/api/share/{share_id}').get_json()
        results.append((info['policy']['allowed'],
                        info['policy'].get('matched_policy', {}).get('remaining_downloads')
                        if info['policy']['allowed'] else None))
        client.get(f'/api/share/{share_id}/download')
    assert results[0][0] is True
    assert results[1][0] is True
    # 第 3 次：策略 2 次配额已用完（分享本身还有 10 次）
    assert results[2][0] is False
    info = client.get(f'/api/share/{share_id}').get_json()
    assert info['policy']['reason'] == pe.REASON_QUOTA_EXHAUSTED


# --------------------------------------------------------------------------
# 展示层：说明 / 预览 / 历史
# --------------------------------------------------------------------------

def test_auto_description(client, auth_token):
    resp = _make_policy(client, auth_token, users=['*'], file_types=['pdf', 'txt'],
                        max_downloads=-1)
    desc = resp.get_json()['policy']['description']
    assert '所有用户' in desc
    assert '.pdf' in desc and '.txt' in desc
    assert '不限次数' in desc


def test_preview_endpoint(client, auth_token):
    resp = client.post('/api/policies/preview', json={
        'name': '预览策略', 'users': ['admin'], 'file_types': ['pdf'], 'max_downloads': 5,
        'scenarios': [
            {'label': '命中', 'username': 'admin', 'filename': 'a.pdf'},
            {'label': '用户不命中', 'username': 'stranger', 'filename': 'a.pdf'},
            {'label': '类型不命中', 'username': 'admin', 'filename': 'a.exe'},
        ],
    }, headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 200
    results = resp.get_json()['results']
    assert results[0]['allowed'] is True
    assert results[1]['reason'] == pe.REASON_USER_FORBIDDEN
    assert results[2]['reason'] == pe.REASON_TYPE_FORBIDDEN


def test_preview_validates_empty_rule(client, auth_token):
    resp = client.post('/api/policies/preview',
                       json={'name': 'x', 'users': [], 'file_types': [], 'max_downloads': 5},
                       headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status_code == 400


def test_preview_quota_simulation(client, auth_token):
    resp = client.post('/api/policies/preview', json={
        'name': '配额策略', 'users': ['admin'], 'file_types': ['pdf'], 'max_downloads': 3,
        'scenarios': [
            {'label': '正常', 'username': 'admin', 'filename': 'a.pdf'},
            {'label': '已取 3 次', 'username': 'admin', 'filename': 'a.pdf', 'simulated_used': 3},
        ],
    }, headers={'Authorization': f'Bearer {auth_token}'})
    results = resp.get_json()['results']
    assert results[0]['allowed'] is True
    assert results[1]['allowed'] is False
    assert results[1]['reason'] == pe.REASON_QUOTA_EXHAUSTED


def test_preview_does_not_persist(client, auth_token):
    client.post('/api/policies/preview', json={
        'name': '仅预览', 'users': ['admin'], 'file_types': ['pdf'], 'max_downloads': 5,
    }, headers={'Authorization': f'Bearer {auth_token}'})
    listed = client.get('/api/policies', headers={'Authorization': f'Bearer {auth_token}'}).get_json()
    assert listed['policies'] == []
    assert listed['enforced'] is False


def test_history_records_decisions_and_config(client, auth_token):
    policy = _make_policy(client, auth_token).get_json()['policy']
    file_id = _upload(client)
    client.get(f'/api/download/{file_id}', headers={'Authorization': f'Bearer {auth_token}'})
    user_token = _auth(client, 'user', 'user123')
    client.get(f'/api/download/{file_id}', headers={'Authorization': f'Bearer {user_token}'})

    logs = client.get('/api/policies/history',
                      headers={'Authorization': f'Bearer {auth_token}'}).get_json()
    config = [l for l in logs if l['event_type'] == 'policy_config']
    allows = [l for l in logs if l['event_type'] == 'download_decision' and l['decision'] == 'allow']
    denies = [l for l in logs if l['event_type'] == 'download_decision' and l['decision'] == 'deny']
    assert any('创建策略' in l['message'] for l in config)
    assert len(allows) == 1 and allows[0]['policy_id'] == policy['id']
    assert len(denies) == 1 and denies[0]['reason'] == pe.REASON_USER_FORBIDDEN
    assert denies[0]['subject'] == 'user'

    # 过滤参数
    only_denies = client.get('/api/policies/history?event_type=download_decision&decision=deny',
                             headers={'Authorization': f'Bearer {auth_token}'}).get_json()
    assert all(l['decision'] == 'deny' for l in only_denies)


# --------------------------------------------------------------------------
# 引擎单元测试（纯函数层）
# --------------------------------------------------------------------------

def test_engine_extension_helpers():
    assert pe.file_extension('A.PDF') == 'pdf'
    assert pe.file_extension('noext') == ''


def test_engine_normalize_validation():
    with pytest.raises(pe.PolicyValidationError):
        pe.normalize_entry_list(None, '授权用户')
    with pytest.raises(pe.PolicyValidationError):
        pe.normalize_entry_list([], '授权用户')
    assert pe.normalize_max_downloads(-1) is None
    assert pe.normalize_max_downloads(None) is None
    assert pe.normalize_max_downloads(7) == 7
    with pytest.raises(pe.PolicyValidationError):
        pe.normalize_max_downloads(0)


def test_extensionless_file_requires_wildcard(client, auth_token):
    """无扩展名文件不能被具体类型规则偷偷放行，只有“所有类型”可以"""
    _make_policy(client, auth_token, file_types=['pdf', '*'])
    # 显式构造无扩展名文件（上传接口本身允许）
    resp = client.post('/api/upload',
                       data={'file': (io.BytesIO(b'raw'), 'Makefile')},
                       content_type='multipart/form-data')
    if resp.status_code == 200:
        file_id = resp.get_json()['file_id']
        r = client.get(f'/api/download/{file_id}',
                       headers={'Authorization': f'Bearer {auth_token}'})
        assert r.status_code == 200

    # 仅有具体类型时，无扩展名文件被拒绝
    policy_id = client.get('/api/policies', headers={'Authorization': f'Bearer {auth_token}'}).get_json()['policies'][0]['id']
    client.put(f'/api/policies/{policy_id}',
               json={'name': '测试策略', 'users': ['admin'], 'file_types': ['pdf'],
                     'max_downloads': 5, 'enabled': True},
               headers={'Authorization': f'Bearer {auth_token}'})
    if resp.status_code == 200:
        r = client.get(f'/api/download/{file_id}',
                       headers={'Authorization': f'Bearer {auth_token}'})
        assert r.status_code == 403
        assert r.get_json()['reason'] == pe.REASON_TYPE_FORBIDDEN


def test_conflict_boundary_touch_not_overlap(client, auth_token):
    """时间窗口端点恰好相接（A.end == B.start）不算重叠"""
    now = time.time()
    _make_policy(client, auth_token, name='A', start_at=now, end_at=now + 100)
    r = _make_policy(client, auth_token, name='B', start_at=now + 100, end_at=now + 200)
    assert r.status_code == 201


def test_wildcard_policy_conflicts_with_everything(client, auth_token):
    _make_policy(client, auth_token, name='通配', users=['*'], file_types=['*'])
    r = _make_policy(client, auth_token, name='具体', users=['admin'], file_types=['pdf'])
    assert r.status_code == 409


def test_deny_without_token_when_policies_exist(client, auth_token):
    _make_policy(client, auth_token)
    file_id = _upload(client)
    # 查询参数带垃圾 token
    r = client.get(f'/api/download/{file_id}?token=garbage')
    assert r.status_code == 401
    assert r.get_json()['reason'] == pe.REASON_TOKEN_INVALID


def test_share_reentry_after_reenable(client, auth_token):
    """停用→重新启用后，公开页重新进入结果恢复放行"""
    policy = _make_policy(client, auth_token).get_json()['policy']
    file_id = _upload(client)
    share_id = client.post('/api/share', json={'file_id': file_id},
                           headers={'Authorization': f'Bearer {auth_token}'}).get_json()['share_id']
    client.patch(f"/api/policies/{policy['id']}", json={'enabled': False},
                 headers={'Authorization': f'Bearer {auth_token}'})
    assert client.get(f'/api/share/{share_id}').get_json()['policy']['allowed'] is False
    client.patch(f"/api/policies/{policy['id']}", json={'enabled': True},
                 headers={'Authorization': f'Bearer {auth_token}'})
    info = client.get(f'/api/share/{share_id}').get_json()
    assert info['policy']['allowed'] is True
    assert client.get(f'/api/share/{share_id}/download').status_code == 200
