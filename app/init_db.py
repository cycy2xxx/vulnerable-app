import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'vulnerable.db')

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    credit_card TEXT,
    secret_note TEXT
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""

SEED_USERS = [
    ('admin', 'admin123', 'admin@example.com', 'admin',
     '4111-1111-1111-1111', 'AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE'),
    ('user1', 'password', 'user1@example.com', 'user',
     '4222-2222-2222-2222', '給与: 450万円'),
    ('user2', 'letmein', 'user2@example.com', 'user',
     '4333-3333-3333-3333', '社内不倫の件は内密に'),
    ('tanaka', 'tanaka2024', 'tanaka@example.com', 'user',
     '4444-4444-4444-4444', '転職活動中。面接は来週火曜'),
]

SEED_POSTS = [
    (1, 'お知らせ', 'システムメンテナンスを実施します。'),
    (1, '管理者メモ', 'DBパスワード: root / toor（本番環境では変更すること）'),
    (2, '自己紹介', 'はじめまして、user1です。よろしくお願いします。'),
    (3, '日記', '今日はいい天気でした。'),
]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.executescript(SCHEMA)

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password, email, role, credit_card, secret_note) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            SEED_USERS,
        )
        cur.executemany(
            "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
            SEED_POSTS,
        )
        conn.commit()

    conn.close()


def reset_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS posts")
    cur.execute("DROP TABLE IF EXISTS users")
    cur.executescript(SCHEMA)
    cur.executemany(
        "INSERT INTO users (username, password, email, role, credit_card, secret_note) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        SEED_USERS,
    )
    cur.executemany(
        "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
        SEED_POSTS,
    )
    conn.commit()
    conn.close()


if __name__ == '__main__':
    init_db()
    print('Database initialized.')
