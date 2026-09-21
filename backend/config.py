"""应用配置"""
import os

PORT = int(os.getenv('PORT', 8636))
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/app/uploads')
DB_FILE = os.getenv('DB_FILE', '/app/data/app.db')
TOKEN_EXPIRE_SECONDS = int(os.getenv('TOKEN_EXPIRE_SECONDS', 300))
RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', 5))
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', 60))
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 52428800))  # 50MB

BLOCKED_EXTENSIONS = {'exe', 'sh', 'bat', 'cmd', 'ps1', 'py', 'php', 'jsp', 'cgi', 'pl'}

SHARE_LINK_EXPIRE_HOURS = int(os.getenv('SHARE_LINK_EXPIRE_HOURS', 24))
SHARE_LINK_MAX_DOWNLOADS = int(os.getenv('SHARE_LINK_MAX_DOWNLOADS', 10))

# 下载授权策略中心：策略管理员账号（逗号分隔）
ADMIN_USERNAMES = set(
    name.strip() for name in os.getenv('ADMIN_USERNAMES', 'admin').split(',') if name.strip()
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
