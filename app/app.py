import os
import sqlite3
import subprocess

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
    send_from_directory,
)

from init_db import DB_PATH, init_db, reset_db

app = Flask(__name__)
app.secret_key = 'super-secret-key-123'  # 脆弱性: ハードコードされた秘密鍵

# ---------------------------------------------------------------------------
# DB初期化
# ---------------------------------------------------------------------------
init_db()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# ダッシュボード
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


# ---------------------------------------------------------------------------
# 認証 (login / logout)
# ---------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            next_url = request.args.get('next', '/')
            return redirect(next_url)
        error = 'ユーザー名またはパスワードが間違っています。'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# ---------------------------------------------------------------------------
# DB リセット
# ---------------------------------------------------------------------------
@app.route('/reset-db')
def reset_database():
    reset_db()
    session.pop('balance', None)
    flash('データベースを初期化しました。', 'success')
    return redirect('/')


# ===========================================================================
# 1. XSS（クロスサイトスクリプティング）
# ===========================================================================
@app.route('/vuln/xss')
def vuln_xss():
    q = request.args.get('q', '')
    return render_template('vuln_xss.html', query=q)


# ===========================================================================
# 2. SQLインジェクション
# ===========================================================================
@app.route('/vuln/sqli', methods=['GET', 'POST'])
def vuln_sqli():
    result = None
    error = None
    username = ''
    password = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = get_db()
        # 脆弱性: f-stringでSQL組み立て
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            rows = conn.execute(query).fetchall()
            if rows:
                result = [dict(r) for r in rows]
            else:
                error = 'ログイン失敗: ユーザーが見つかりません。'
        except Exception as e:
            error = f'SQLエラー: {e}'
        conn.close()
    return render_template('vuln_sqli.html', result=result, error=error,
                           username=username, password=password)


# ===========================================================================
# 3. CSRF（クロスサイトリクエストフォージェリ）
# ===========================================================================
@app.route('/vuln/csrf', methods=['GET', 'POST'])
def vuln_csrf():
    # セッションに残高を保持
    if 'balance' not in session:
        session['balance'] = 100000
    message = None
    if request.method == 'POST':
        to = request.form.get('to', '')
        amount = int(request.form.get('amount', 0))
        if amount > session['balance']:
            message = 'エラー: 残高不足です。'
        elif amount <= 0:
            message = 'エラー: 金額は1以上にしてください。'
        else:
            session['balance'] -= amount
            message = f'{to} に ¥{amount:,} を送金しました。'
    return render_template('vuln_csrf.html', balance=session['balance'],
                           message=message)


# ===========================================================================
# 4. 認証の不備
# ===========================================================================
@app.route('/vuln/auth', methods=['GET', 'POST'])
def vuln_auth():
    result = None
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            result = dict(user)
        else:
            error = 'ログイン失敗'
    return render_template('vuln_auth.html', result=result, error=error,
                           session_data=dict(session))


# ===========================================================================
# 5. 機密情報の露出
# ===========================================================================
@app.route('/vuln/exposure')
def vuln_exposure():
    conn = get_db()
    users = [dict(r) for r in conn.execute("SELECT * FROM users").fetchall()]
    conn.close()
    return render_template('vuln_exposure.html', users=users)


@app.route('/api/users')
def api_users():
    conn = get_db()
    users = [dict(r) for r in conn.execute("SELECT * FROM users").fetchall()]
    conn.close()
    return jsonify(users)


# ===========================================================================
# 6. OSコマンドインジェクション
# ===========================================================================
@app.route('/vuln/cmdi', methods=['GET', 'POST'])
def vuln_cmdi():
    output = None
    host = ''
    if request.method == 'POST':
        host = request.form.get('host', '')
        # 脆弱性: shell=True + ユーザー入力をそのまま埋め込み
        try:
            result = subprocess.run(
                f'ping -c 3 {host}',
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = 'タイムアウト: コマンドの実行に10秒以上かかりました。'
        except Exception as e:
            output = f'エラー: {e}'
    return render_template('vuln_cmdi.html', output=output, host=host)


# ===========================================================================
# 7. セキュリティ設定ミス
# ===========================================================================
@app.route('/vuln/misconfig')
def vuln_misconfig():
    info = {
        'debug_mode': app.debug,
        'secret_key': app.secret_key,
        'server_header': 'Werkzeug (Python/Flask)',
        'default_credentials': 'admin / admin123',
    }
    return render_template('vuln_misconfig.html', info=info)


@app.route('/files/')
@app.route('/files/<path:filename>')
def directory_listing(filename=''):
    data_dir = os.path.join(app.root_path, 'data')
    if filename:
        return send_from_directory(data_dir, filename)
    files = os.listdir(data_dir)
    return render_template('vuln_misconfig.html', info=None, files=files,
                           directory=True)


# ===========================================================================
# 8. ディレクトリトラバーサル
# ===========================================================================
@app.route('/vuln/traversal')
def vuln_traversal():
    filename = request.args.get('file', '')
    content = None
    error = None
    if filename:
        # 脆弱性: パス検証なし
        filepath = os.path.join(app.root_path, 'data', filename)
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            error = f'ファイルが見つかりません: {filename}'
        except IsADirectoryError:
            error = f'{filename} はディレクトリです。'
        except Exception as e:
            error = f'エラー: {e}'
    return render_template('vuln_traversal.html', filename=filename,
                           content=content, error=error)


# ===========================================================================
# 9. アクセス制御の不備
# ===========================================================================
@app.route('/vuln/access')
def vuln_access():
    return render_template('vuln_access.html')


@app.route('/vuln/access/profile/<int:user_id>')
def vuln_access_profile(user_id):
    # 脆弱性: 認可チェックなし（IDOR）
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not user:
        return 'ユーザーが見つかりません', 404
    return render_template('profile.html', user=dict(user))


@app.route('/admin')
def admin_panel():
    # 脆弱性: 認証・認可チェックなし
    conn = get_db()
    users = [dict(r) for r in conn.execute("SELECT * FROM users").fetchall()]
    posts = [dict(r) for r in conn.execute("SELECT * FROM posts").fetchall()]
    conn.close()
    return render_template('admin.html', users=users, posts=posts)


# ===========================================================================
# 10. オープンリダイレクト
# ===========================================================================
@app.route('/vuln/redirect')
def vuln_redirect():
    url = request.args.get('url', '')
    if url:
        # 脆弱性: リダイレクト先の検証なし
        return redirect(url)
    return render_template('vuln_redirect.html')


# ---------------------------------------------------------------------------
# メイン
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
