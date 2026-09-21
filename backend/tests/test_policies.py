"""下载授权策略中心测试：配置、校验、冲突、判定一致性、历史核对"""
import io
import time
from datetime import datetime

import pytest


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
def login(client, username, password):
    from auth import rate_limit_store
    rate_limit_store.clear()
    resp = client.post('/api/auth', json={'username': username, 'password': password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['token']


def auth(token):
    return {'Authorization': f'Bearer {token}'}


def upload(client, name='report.txt', content=b'data'):
    resp = client.post(
        '/api/upload',
        data={'file': (io.BytesIO(content), name)},
        content_type='multipart/form-data'
    )
    assert resp.status_code == 200
    return resp.get_json()['file_id']


def make_share(client, admin_token, file_id, expire_hours=24, max_downloads=10):
    resp = client.post(
        '/api/share',
        json={'file_id': file_id, 'expire_hours': expire_hours, 'max_downloads': max_downloads},
        headers=auth(admin_token)
    )
    return resp.get_json()['share_id']


def create_policy(client, token, payload):
    return client.post('/api/policies', json=payload, headers=auth(token))


@pytest.fixture
def admin_token(client):
    return login(client, 'admin', 'admin123')


@pytest.fixture
def user_token(client):
    return login(client, 'user', 'user123')


# ---------------------------------------------------------------------------
# 一、权限与配置层校验
# ---------------------------------------------------------------------------
def test_policy_center_requires_admin(client, user_token):
    """非管理员不能访问策略中心"""
    resp = client.get('/api/policies', headers=auth(user_token))
    assert resp.status_code == 403


def test_policy_center_requires_login(client):
    resp = client.get('/api/policies')
    assert resp.status_code == 401


def test_empty_policy_is_rejected(client, admin_token):
    """空规则：四个维度都不限定，必须拒绝保存（防止无条件放行）"""
    resp = create_policy(client, admin_token, {
        'name': '空规则', 'usernames': '', 'extensions': '',
        'start_time': '', 'end_time': '', 'max_downloads': ''
    })
    assert resp.status_code == 400
    body = resp.get_json()
    assert any('空' in e for e in body['errors'])


def test_policy_validation_errors(client, admin_token):
    """未知用户、非法扩展名、非法时间、非法次数都要报原因"""
    resp = create_policy(client, admin_token, {
        'name': '坏策略', 'usernames': 'ghost', 'extensions': 'ex$e',
        'start_time': '25:00', 'end_time': '09:00', 'max_downloads': -3
    })
    assert resp.status_code == 400
    errors = ' '.join(resp.get_json()['errors'])
    assert 'ghost' in errors
    assert '不合法' in errors
    assert '时间' in errors
    assert '次数' in errors


def test_time_window_inverted_is_allowed_as_overnight(client, admin_token):
    """22:00-06:00 视为跨午夜窗口，可保存"""
    resp = create_policy(client, admin_token, {
        'name': '夜间窗口', 'usernames': 'user', 'extensions': 'txt',
        'start_time': '22:00', 'end_time': '06:00', 'max_downloads': 5
    })
    assert resp.status_code == 201
    assert resp.get_json()['policy']['start_time'] == '22:00'


def test_overlapping_policies_warn_but_save(client, admin_token):
    """重叠规则：创建时给出冲突提示，但仍允许保存（判定阶段才拦截）"""
    first = create_policy(client, admin_token, {
        'name': '策略A', 'usernames': 'user', 'extensions': 'txt',
        'max_downloads': 3
    })
    assert first.status_code == 201
    assert first.get_json()['warnings'] == []

    second = create_policy(client, admin_token, {
        'name': '策略B', 'usernames': 'user', 'extensions': 'txt',
        'max_downloads': 9
    })
    assert second.status_code == 201
    warnings = second.get_json()['warnings']
    assert len(warnings) == 1
    assert '策略A' in warnings[0] and '重叠' in warnings[0]
    assert '取件次数限制不一致：9 vs 3' in warnings[0]


def test_policy_description_is_generated(client, admin_token):
    """策略说明要把四个维度讲清楚"""
    resp = create_policy(client, admin_token, {
        'name': '说明测试', 'usernames': 'user,test', 'extensions': 'pdf,zip',
        'start_time': '09:00', 'end_time': '18:00', 'max_downloads': 2
    })
    text = resp.get_json()['policy']['description_text']
    assert 'user' in text and 'test' in text
    assert 'pdf' in text and 'zip' in text
    assert '09:00' in text and '18:00' in text
    assert '2 次/人' in text


def test_toggle_disable_and_enable(client, admin_token):
    pid = create_policy(client, admin_token, {
        'name': '待停用', 'usernames': 'user', 'extensions': 'txt'
    }).get_json()['policy']['id']

    off = client.post(f'/api/policies/{pid}/toggle', headers=auth(admin_token))
    assert off.get_json()['policy']['enabled'] is False
    assert any('停用' in w for w in off.get_json()['warnings'])

    on = client.post(f'/api/policies/{pid}/toggle', headers=auth(admin_token))
    assert on.get_json()['policy']['enabled'] is True


def test_toggle_policy_without_time_window(client, admin_token):
    """不设时间范围的策略也能正常启停（覆盖时间窗空值边界）"""
    pid = create_policy(client, admin_token, {
        'name': '仅用户维度', 'usernames': 'user'
    }).get_json()['policy']['id']
    off = client.post(f'/api/policies/{pid}/toggle', headers=auth(admin_token))
    assert off.status_code == 200
    on = client.post(f'/api/policies/{pid}/toggle', headers=auth(admin_token))
    assert on.status_code == 200
    assert on.get_json()['policy']['enabled'] is True


# ---------------------------------------------------------------------------
# 二、判定：默认放行 / 拒绝原因
# ---------------------------------------------------------------------------
def test_download_allowed_when_no_policies(client, user_token):
    """没有任何策略时沿用默认放行，已有合法请求不被误伤"""
    file_id = upload(client)
    resp = client.get(f'/api/download/{file_id}', headers=auth(user_token))
    assert resp.status_code == 200
    assert resp.data == b'data'


def test_matching_policy_allows_with_quota_info(client, admin_token, user_token):
    create_policy(client, admin_token, {
        'name': 'user的txt', 'usernames': 'user', 'extensions': 'txt',
        'max_downloads': 3
    })
    file_id = upload(client)
    resp = client.get(f'/api/download/{file_id}', headers=auth(user_token))
    assert resp.status_code == 200


def test_no_matching_policy_denies(client, admin_token, user_token):
    """用户/类型不被任何策略覆盖 -> 拒绝并说明"""
    create_policy(client, admin_token, {
        'name': '只给pdf', 'usernames': 'user', 'extensions': 'pdf'
    })
    file_id = upload(client, name='note.txt')
    resp = client.get(f'/api/download/{file_id}', headers=auth(user_token))
    assert resp.status_code == 403
    decision = resp.get_json()['decision']
    assert decision['allowed'] is False
    assert decision['reason'] == 'no_matching_policy'
    assert '没有适用' in decision['reason_text']


def test_disabled_policy_does_not_pass(client, admin_token, user_token):
    """唯一命中的策略停用 -> 拒绝，不能放行"""
    pid = create_policy(client, admin_token, {
        'name': '即将停用', 'usernames': 'user', 'extensions': 'txt'
    }).get_json()['policy']['id']
    client.post(f'/api/policies/{pid}/toggle', headers=auth(admin_token))

    file_id = upload(client)
    resp = client.get(f'/api/download/{file_id}', headers=auth(user_token))
    assert resp.status_code == 403
    assert resp.get_json()['decision']['reason'] == 'policy_disabled'


def test_expired_token_denies(client, admin_token, user_token, db_conn):
    """失效令牌：明确拒绝，不进入策略判定"""
    create_policy(client, admin_token, {
        'name': '放行txt', 'usernames': 'user', 'extensions': 'txt'
    })
    file_id = upload(client)

    cursor = db_conn.cursor()
    cursor.execute('UPDATE tokens SET expires_at = ? WHERE token = ?',
                   (time.time() - 10, user_token))
    db_conn.commit()

    resp = client.get(f'/api/download/{file_id}', headers=auth(user_token))
    assert resp.status_code == 401
    assert resp.get_json()['decision']['reason'] == 'invalid_token'


def test_conflicting_policies_deny(client, admin_token, user_token):
    """重叠的启用策略同时命中 -> 冲突，拒绝并列明策略名"""
    create_policy(client, admin_token, {
        'name': '冲突一', 'usernames': 'user', 'extensions': 'txt', 'max_downloads': 1
    })
    create_policy(client, admin_token, {
        'name': '冲突二', 'usernames': 'user', 'extensions': 'txt', 'max_downloads': 9
    })
    file_id = upload(client)
    resp = client.get(f'/api/download/{file_id}', headers=auth(user_token))
    assert resp.status_code == 403
    decision = resp.get_json()['decision']
    assert decision['reason'] == 'policy_conflict'
    assert '冲突一' in decision['reason_detail'] and '冲突二' in decision['reason_detail']


def test_quota_exhausted_denies(client, admin_token, user_token):
    """取件次数用尽 -> 拒绝并显示已用/上限"""
    create_policy(client, admin_token, {
        'name': '限2次', 'usernames': 'user', 'extensions': 'txt', 'max_downloads': 2
    })
    file_id = upload(client)
    for _ in range(2):
        assert client.get(f'/api/download/{file_id}', headers=auth(user_token)).status_code == 200

    third = client.get(f'/api/download/{file_id}', headers=auth(user_token))
    assert third.status_code == 403
    decision = third.get_json()['decision']
    assert decision['reason'] == 'quota_exhausted'
    assert decision['used'] == 2 and decision['limit'] == 2


def test_quota_is_per_user(client, admin_token, user_token):
    """取件次数按用户分别统计"""
    test_token = login(client, 'test', 'test123')
    create_policy(client, admin_token, {
        'name': 'txt限额', 'usernames': 'user,test', 'extensions': 'txt', 'max_downloads': 1
    })
    file_id = upload(client)

    assert client.get(f'/api/download/{file_id}', headers=auth(user_token)).status_code == 200
    # user 用完，test 仍可取件
    assert client.get(f'/api/download/{file_id}', headers=auth(test_token)).status_code == 200
    assert client.get(f'/api/download/{file_id}', headers=auth(test_token)).status_code == 403


def test_time_window_blocks_outside_hours(client, admin_token, user_token, monkeypatch):
    """当前时间不在允许时段 -> 拒绝"""
    import policies
    create_policy(client, admin_token, {
        'name': '仅凌晨', 'usernames': 'user', 'extensions': 'txt',
        'start_time': '02:00', 'end_time': '04:00'
    })
    file_id = upload(client)

    class FakeDateTime:
        @classmethod
        def now(cls):
            return datetime(2026, 9, 21, 12, 0)  # 正午，不在 02-04

    monkeypatch.setattr(policies, 'datetime', FakeDateTime)
    resp = client.get(f'/api/download/{file_id}', headers=auth(user_token))
    assert resp.status_code == 403
    assert resp.get_json()['decision']['reason'] == 'time_outside_window'

    class FakeDateTimeNight:
        @classmethod
        def now(cls):
            return datetime(2026, 9, 21, 3, 0)

    monkeypatch.setattr(policies, 'datetime', FakeDateTimeNight)
    assert client.get(f'/api/download/{file_id}', headers=auth(user_token)).status_code == 200


def test_overnight_window(client, admin_token, user_token, monkeypatch):
    """跨午夜窗口 22:00-06:00：23点放行，12点拒绝"""
    import policies
    create_policy(client, admin_token, {
        'name': '夜间', 'usernames': 'user', 'extensions': 'txt',
        'start_time': '22:00', 'end_time': '06:00'
    })
    file_id = upload(client)

    monkeypatch.setattr(policies, 'datetime', type('D', (), {
        'now': staticmethod(lambda: datetime(2026, 9, 21, 23, 30))}))
    assert client.get(f'/api/download/{file_id}', headers=auth(user_token)).status_code == 200

    monkeypatch.setattr(policies, 'datetime', type('D', (), {
        'now': staticmethod(lambda: datetime(2026, 9, 21, 12, 0))}))
    assert client.get(f'/api/download/{file_id}', headers=auth(user_token)).status_code == 403


# ---------------------------------------------------------------------------
# 三、三个入口判定一致性
# ---------------------------------------------------------------------------
def test_decision_consistent_across_directory_and_share(client, admin_token, user_token):
    """同一用户同一文件：目录入口与公开分享页（登录态）结论必须一致"""
    create_policy(client, admin_token, {
        'name': '只准pdf', 'usernames': 'user', 'extensions': 'pdf'
    })
    txt_id = upload(client, name='doc.txt')
    share_id = make_share(client, admin_token, txt_id)

    # 目录入口
    dir_resp = client.get(f'/api/download/{txt_id}', headers=auth(user_token))
    assert dir_resp.status_code == 403
    dir_reason = dir_resp.get_json()['decision']['reason']

    # 公开分享页（带登录令牌，即重新进入的页面）
    info_resp = client.get(f'/api/share/{share_id}', headers=auth(user_token))
    assert info_resp.status_code == 200
    preview = info_resp.get_json()['decision']
    assert preview['allowed'] is False
    assert preview['reason'] == dir_reason == 'no_matching_policy'

    # 分享下载入口
    share_dl = client.get(f'/api/share/{share_id}/download', headers=auth(user_token))
    assert share_dl.status_code == 403
    assert share_dl.get_json()['decision']['reason'] == dir_reason


def test_share_download_with_token_respects_quota_and_no_double_count(
        client, admin_token, user_token):
    """登录用户走分享入口同样受取件次数限制，且不累加分享链接自身计数"""
    create_policy(client, admin_token, {
        'name': '限1次', 'usernames': 'user', 'extensions': 'txt', 'max_downloads': 1
    })
    file_id = upload(client)
    share_id = make_share(client, admin_token, file_id)

    first = client.get(f'/api/share/{share_id}/download', headers=auth(user_token))
    assert first.status_code == 200

    # 分享链接计数不应被登录态取件累加
    info = client.get(f'/api/share/{share_id}').get_json()
    assert info['download_count'] == 0

    second = client.get(f'/api/share/{share_id}/download', headers=auth(user_token))
    assert second.status_code == 403
    assert second.get_json()['decision']['reason'] == 'quota_exhausted'

    # 同一文件从目录入口再试，结论一致（次数已用尽）
    again = client.get(f'/api/download/{file_id}', headers=auth(user_token))
    assert again.status_code == 403
    assert again.get_json()['decision']['reason'] == 'quota_exhausted'


def test_anonymous_share_still_works_when_policies_exist(client, admin_token, user_token):
    """访客（无令牌）仍按分享链接规则下载，不被策略误伤"""
    create_policy(client, admin_token, {
        'name': '仅user', 'usernames': 'user', 'extensions': 'pdf'
    })
    file_id = upload(client, name='public.txt')
    share_id = make_share(client, admin_token, file_id)

    resp = client.get(f'/api/share/{share_id}/download')
    assert resp.status_code == 200
    assert resp.data == b'data'


def test_reentry_after_share_expiry_uses_policy_for_logged_in_user(
        client, admin_token, user_token, db_conn):
    """重新进入已过期分享页：登录用户仍按策略判定，可正常取件"""
    create_policy(client, admin_token, {
        'name': 'user任意类型', 'usernames': 'user'
    })
    file_id = upload(client)
    share_id = make_share(client, admin_token, file_id)

    cursor = db_conn.cursor()
    cursor.execute('UPDATE share_links SET expires_at = ? WHERE id = ?',
                   (time.time() - 3600, share_id))
    db_conn.commit()

    # 访客：过期，404
    guest = client.get(f'/api/share/{share_id}/download')
    assert guest.status_code == 404

    # 登录用户：策略允许，200
    resp = client.get(f'/api/share/{share_id}/download', headers=auth(user_token))
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 四、结果预览与历史核对
# ---------------------------------------------------------------------------
def test_preview_does_not_consume_quota(client, admin_token, user_token):
    """命中结果预览不落历史、不消耗次数"""
    create_policy(client, admin_token, {
        'name': '预览限额', 'usernames': 'user', 'extensions': 'txt', 'max_downloads': 1
    })

    for _ in range(3):
        resp = client.post('/api/policies/preview', json={
            'username': 'user', 'filename': 'x.txt', 'source': 'directory'
        }, headers=auth(admin_token))
        assert resp.status_code == 200
        decision = resp.get_json()['decision']
        assert decision['allowed'] is True
        assert decision['used'] == 0 and decision['remaining'] == 1

    # 真正下载仍然成功（预览没有占用唯一一次名额）
    file_id = upload(client)
    assert client.get(f'/api/download/{file_id}', headers=auth(user_token)).status_code == 200


def test_preview_denied_case(client, admin_token):
    create_policy(client, admin_token, {
        'name': '只给admin的pdf', 'usernames': 'admin', 'extensions': 'pdf'
    })
    resp = client.post('/api/policies/preview', json={
        'username': 'user', 'filename': 'a.txt'
    }, headers=auth(admin_token))
    decision = resp.get_json()['decision']
    assert decision['allowed'] is False
    assert decision['reason'] == 'no_matching_policy'


def test_preview_validates_inputs(client, admin_token):
    resp = client.post('/api/policies/preview',
                       json={'username': 'nobody', 'filename': 'a.txt'},
                       headers=auth(admin_token))
    assert resp.status_code == 400


def test_decision_logs_recorded_and_queryable(client, admin_token, user_token):
    """历史核对：真实下载（放行与拒绝）都有记录，可按结论过滤"""
    create_policy(client, admin_token, {
        'name': 'pdf限定', 'usernames': 'user', 'extensions': 'pdf'
    })
    allowed_id = upload(client, name='ok.pdf')
    denied_id = upload(client, name='no.txt')

    client.get(f'/api/download/{allowed_id}', headers=auth(user_token))
    client.get(f'/api/download/{denied_id}', headers=auth(user_token))

    logs = client.get('/api/policies/decision-logs', headers=auth(admin_token)).get_json()
    assert logs['total'] == 2

    allow_logs = client.get(
        '/api/policies/decision-logs?decision=allow&username=user',
        headers=auth(admin_token)
    ).get_json()
    assert allow_logs['total'] == 1
    item = allow_logs['items'][0]
    assert item['filename'] == 'ok.pdf'
    assert item['source'] == 'directory'
    assert item['matched_policy_name'] == 'pdf限定'
    assert item['enforced'] == 1

    deny_logs = client.get(
        '/api/policies/decision-logs?decision=deny', headers=auth(admin_token)
    ).get_json()
    assert deny_logs['total'] == 1
    assert deny_logs['items'][0]['reason'] == 'no_matching_policy'


def test_log_sources_distinguish_entry_points(client, admin_token, user_token):
    """历史中能区分目录 / 公开分享 / 重新进入三种来源"""
    create_policy(client, admin_token, {'name': 'user全包', 'usernames': 'user'})
    file_id = upload(client)
    share_id = make_share(client, admin_token, file_id)

    client.get(f'/api/download/{file_id}', headers=auth(user_token))
    client.get(f'/api/share/{share_id}/download', headers=auth(user_token))
    # 重新进入页面（GET 分享信息带令牌）是 dry-run，enforced=0
    client.get(f'/api/share/{share_id}', headers=auth(user_token))

    logs = client.get('/api/policies/decision-logs', headers=auth(admin_token)).get_json()
    # 只统计 enforced 的放行 + 上面 dry-run 一条
    enforced_sources = {i['source'] for i in logs['items'] if i['enforced'] == 1}
    assert enforced_sources == {'directory', 'share_public'}

    # dry-run（重新进入预判）也可核对，但不计入次数
    reentry = client.get(
        '/api/policies/decision-logs?source=share_reentry', headers=auth(admin_token)
    ).get_json()
    assert reentry['total'] == 1
    assert reentry['items'][0]['enforced'] == 0
