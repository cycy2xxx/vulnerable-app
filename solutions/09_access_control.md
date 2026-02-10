# 9. アクセス制御の不備

## 概要
認可チェックの欠如により、URLのIDを変更するだけで他ユーザーのデータにアクセスできる（IDOR）、または認証なしで管理機能にアクセスできる脆弱性。

## 参考
- IPA「安全なウェブサイトの作り方」: 認可・認証の不備
- OWASP Top 10 2021: A01:2021 – Broken Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-285: Improper Authorization

## 脆弱なコード

```python
# IDOR: 認可チェックなし
@app.route('/vuln/access/profile/<int:user_id>')
def vuln_access_profile(user_id):
    conn = get_db()
    # ログインユーザーとuser_idの一致を検証していない
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return render_template('profile.html', user=dict(user))

# 管理パネル: 認証チェックなし
@app.route('/admin')
def admin_panel():
    # session のチェックがない
    users = conn.execute("SELECT * FROM users").fetchall()
    return render_template('admin.html', users=users)
```

## 攻撃手順とペイロード例

### IDOR（安全でない直接オブジェクト参照）
```
/vuln/access/profile/1  → adminの個人情報
/vuln/access/profile/2  → user1の個人情報
/vuln/access/profile/3  → user2の個人情報
/vuln/access/profile/4  → tanakaの個人情報
```

ログインしていなくても、IDを列挙するだけで全ユーザーの情報（パスワード、カード番号、秘密メモ）が閲覧可能。

### 管理パネルへの不正アクセス
```
/admin
```
認証なしで管理パネルにアクセスし、全ユーザーの情報と投稿を閲覧できる。

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/app.py` | 273-281 | `vuln_access_profile()` — `session` の確認なし。URL の `user_id` だけでデータ返却 |
| `app/app.py` | 284-291 | `admin_panel()` — `session['role']` の確認なし。誰でもアクセス可能 |
| `app/app.py` | 182-187 | `/api/users` — 認証なしでユーザー全情報を返すAPI |
| `app/app.py` | 76-81 | `/reset-db` — 認証なしでDB初期化が可能（破壊的操作） |

### コードレビューで探すパターン（grep対象）
```bash
# 全ルート定義を列挙
grep -rn '@app\.route' app/app.py

# 認証チェック（session確認）があるルートとないルートを比較
grep -A3 '@app\.route' app/app.py | grep -E 'route|session'

# login_required デコレータの有無
grep -rn 'login_required\|admin_required\|requires_auth' app/

# IDベースのリソースアクセス（IDOR候補）
grep -rn '<int:.*id>\|<user_id>\|<int:id>' app/app.py

# session のチェックパターン
grep -rn "session\[.*user_id\|session\.get.*user" app/app.py

# 認可チェック（ロール確認）
grep -rn "session\[.*role\|session\.get.*role\|is_admin" app/
```

### 診断の勘所
1. **全エンドポイントの認証マトリクス作成**: 各ルートに対して「認証要否」「必要なロール」を一覧化し、実装と照合する
2. **デコレータの確認**: `@login_required` 等の認証デコレータが定義されているか、使われているか
3. **IDOR候補の特定**: URLにID（`/profile/<int:user_id>`）を含むルートで、`session['user_id'] == user_id` の検証があるか
4. **管理機能の保護**: `/admin` 等の管理系ルートに `session['role'] == 'admin'` のチェックがあるか
5. **水平権限昇格**: 同じロール間で他ユーザーのリソースにアクセスできないか
6. **垂直権限昇格**: 一般ユーザーが管理者機能にアクセスできないか
7. **破壊的操作の保護**: `/reset-db` のような破壊的操作に認証がかかっているか

## 対策（修正コード + セキュリティ原則）

### 修正方法: 認証・認可チェック
```python
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            return 'Forbidden', 403
        return f(*args, **kwargs)
    return decorated

@app.route('/vuln/access/profile/<int:user_id>')
@login_required
def vuln_access_profile(user_id):
    # ログインユーザー自身のプロファイルのみアクセス可能
    if session['user_id'] != user_id and session.get('role') != 'admin':
        return 'Forbidden', 403
    ...

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    ...
```

### セキュリティ原則
- **認証の必須化**: 全ての保護対象エンドポイントで認証チェック
- **認可の検証**: リソースの所有者とリクエスト元ユーザーの一致を検証
- **ロールベースアクセス制御**: 管理機能にはadminロールを要求
- **予測困難なID**: 連番IDの代わりにUUIDを使用
