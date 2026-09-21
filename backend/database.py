"""数据库操作"""
import sqlite3
import hashlib
from config import DB_FILE


def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库表"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            path TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS share_links (
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            created_by TEXT NOT NULL,
            expires_at REAL,
            max_downloads INTEGER,
            download_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS download_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            usernames TEXT DEFAULT '',
            extensions TEXT DEFAULT '',
            start_time TEXT,
            end_time TEXT,
            max_downloads INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policy_decision_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            file_id TEXT,
            filename TEXT,
            extension TEXT,
            source TEXT DEFAULT 'directory',
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            reason_detail TEXT DEFAULT '',
            matched_policy_id INTEGER,
            matched_policy_name TEXT,
            enforced INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    default_users = [
        ('admin', hashlib.sha256('admin123'.encode()).hexdigest()),
        ('user', hashlib.sha256('user123'.encode()).hexdigest()),
        ('test', hashlib.sha256('test123'.encode()).hexdigest())
    ]
    for username, password_hash in default_users:
        cursor.execute(
            'INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )

    conn.commit()
    conn.close()
