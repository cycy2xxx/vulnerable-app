# 4. 認証の不備

## 概要
パスワードの平文保存、弱いパスワードの許可、アカウントロック機構の欠如、レート制限なしなど、認証機構の設計不備。

## 参考
- IPA「安全なウェブサイトの作り方」: 1.8 認証
- OWASP Top 10 2021: A07:2021 – Identification and Authentication Failures
- CWE-521: Weak Password Requirements
- CWE-256: Plaintext Storage of a Password

## 脆弱なコード

```python
# パスワードを平文で比較（ハッシュ化されていない）
user = conn.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, password),
).fetchone()

# シードデータ: パスワードが平文
SEED_USERS = [
    ('admin', 'admin123', ...),      # 弱いパスワード
    ('user1', 'password', ...),      # 辞書攻撃で容易に突破
    ('user2', 'letmein', ...),       # 同上
]

# アカウントロック機構なし、レート制限なし
```

## 攻撃手順とペイロード例

### 弱いパスワードでのログイン
- admin / admin123
- user1 / password
- user2 / letmein

### ブルートフォース攻撃（例: hydra）
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost -s 5000 http-post-form "/vuln/auth:username=^USER^&password=^PASS^:ログイン失敗"
```

何度試行してもアカウントがロックされない。

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/init_db.py` | 10 | `password TEXT NOT NULL` — パスワードカラムにハッシュ化の形跡なし |
| `app/init_db.py` | 27-36 | シードデータのパスワードが平文（`admin123`, `password`, `letmein`） |
| `app/app.py` | 52-55 | `WHERE username = ? AND password = ?` — 平文パスワードとの直接比較 |
| `app/app.py` | 147-168 | `vuln_auth()` — ログイン失敗回数のカウントやロック処理がない |
| `app/app.py` | 164 | `result = dict(user)` — ユーザー全情報（パスワード含む）をレスポンスに含めている |

### コードレビューで探すパターン（grep対象）
```bash
# パスワードのハッシュ化ライブラリの使用有無
grep -rn 'bcrypt\|argon2\|pbkdf2\|generate_password_hash\|check_password_hash' app/
grep -rn 'hashlib\|sha256\|md5' app/

# パスワードを平文で比較している箇所
grep -rn "password = ?" app/
grep -rn "password.*=.*request" app/

# アカウントロック・レート制限の実装有無
grep -rn 'login_attempt\|failed_count\|rate_limit\|Limiter' app/

# セッション設定
grep -rn 'SESSION_\|session\[' app/app.py

# パスワードポリシーの検証有無
grep -rn 'len(password)\|password.*min\|validate.*password' app/
```

### 診断の勘所
1. **パスワード保存方式**: DBスキーマとシードデータで平文保存を確認。`init_db.py` のスキーマに注目
2. **ハッシュ化ライブラリの存在**: `requirements.txt` に bcrypt / argon2 等が含まれていなければ未実装の可能性大
3. **認証ロジックの網羅的確認**: `password` を含むクエリを全て追跡
4. **ブルートフォース対策**: ログイン試行回数のカウント処理、ロック処理、レート制限ミドルウェアの有無
5. **セッション管理**: ログイン成功時にセッションIDを再生成しているか（セッション固定攻撃対策）
6. **弱いパスワードの許可**: ユーザー登録時のパスワード強度チェックの有無

## 対策（修正コード + セキュリティ原則）

### 修正方法: パスワードハッシュ化 + レート制限
```python
from werkzeug.security import generate_password_hash, check_password_hash

# 保存時
hashed = generate_password_hash(password)

# 検証時
user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
if user and check_password_hash(user['password'], password):
    # ログイン成功
```

### セキュリティ原則
- **パスワードハッシュ化**: bcrypt, argon2, PBKDF2 等を使用
- **パスワードポリシー**: 最低8文字、大小英数字記号混在を要求
- **アカウントロック**: N回連続失敗でアカウントを一時ロック
- **レート制限**: IPアドレスごとの試行回数を制限（Flask-Limiter等）
- **多要素認証**: 重要なアカウントにはMFAを導入
