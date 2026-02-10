# 5. 機密情報の露出

## 概要
APIレスポンスやHTMLページにパスワード、クレジットカード番号、秘密メモなどの機密情報がフィルタリングされずに含まれている問題。

## 参考
- IPA「安全なウェブサイトの作り方」: 出力値の扱い不備
- OWASP Top 10 2021: A02:2021 – Cryptographic Failures
- CWE-200: Exposure of Sensitive Information

## 脆弱なコード

```python
@app.route('/api/users')
def api_users():
    conn = get_db()
    # SELECT * で全カラム（パスワード、カード番号含む）を取得
    users = [dict(r) for r in conn.execute("SELECT * FROM users").fetchall()]
    conn.close()
    return jsonify(users)  # そのままJSON返却
```

## 攻撃手順とペイロード例

### APIから機密情報を取得
```bash
curl http://localhost:5000/api/users | jq .
```

レスポンス例:
```json
[
  {
    "id": 1,
    "username": "admin",
    "password": "admin123",
    "email": "admin@example.com",
    "credit_card": "4111-1111-1111-1111",
    "secret_note": "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE"
  }
]
```

### HTMLソースからの情報取得
ブラウザの「ページのソースを表示」で機密情報が確認できる。

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/app.py` | 177 | `SELECT * FROM users` — 全カラム取得（password, credit_card, secret_note 含む） |
| `app/app.py` | 182-187 | `/api/users` — 認証なしのAPIが全フィールドをJSON返却 |
| `app/app.py` | 185 | `jsonify(users)` — フィルタリングなしでそのままシリアライズ |
| `app/templates/vuln_exposure.html` | テーブル部分 | テンプレートでパスワード・カード番号を表示 |
| `app/init_db.py` | 28-29 | シードデータにAWSキーやカード番号がハードコード |

### コードレビューで探すパターン（grep対象）
```bash
# SELECT * の使用（全カラム取得 = 不要な機密情報も含まれる可能性）
grep -rn 'SELECT \*' app/

# APIエンドポイントの特定
grep -rn 'jsonify\|json.dumps\|make_response.*json' app/

# 認証チェックなしのAPIルート
grep -B5 'jsonify' app/app.py | grep -v 'session\|login_required'

# 機密データのカラム名がコードに含まれているか
grep -rn 'password\|credit_card\|secret_note\|secret_key\|token' app/

# レスポンスヘッダの設定
grep -rn 'Cache-Control\|X-Content-Type\|Strict-Transport' app/
```

### 診断の勘所
1. **SELECT * の全数検査**: `SELECT *` は不要なカラムも返すため原則禁止。全クエリでカラムを明示しているか確認
2. **APIレスポンスのフィールド制御**: `jsonify()` に渡すデータに機密フィールドが含まれていないか
3. **認証・認可の有無**: APIエンドポイントに認証チェックがあるか。未認証で叩けるAPIを列挙する
4. **データフロー**: DB → Python変数 → テンプレート/JSON の経路で、どこかでフィルタリングされているか
5. **ハードコードされた機密情報**: ソースコード内のAPIキー、パスワード、トークン等をスキャン
6. **HTTPヘッダ**: レスポンスに `Cache-Control: no-store` がないと、機密データがブラウザキャッシュに残る

## 対策（修正コード + セキュリティ原則）

### 修正方法: フィールドフィルタリング
```python
@app.route('/api/users')
def api_users():
    conn = get_db()
    # 必要なフィールドのみ取得
    users = [dict(r) for r in conn.execute(
        "SELECT id, username, email FROM users"
    ).fetchall()]
    conn.close()
    return jsonify(users)
```

### セキュリティ原則
- **最小権限の原則**: 必要最小限のデータのみ返す
- **データマスキング**: カード番号は `****-****-****-1111` のように部分マスク
- **パスワードハッシュ化**: パスワードは平文で保存・返却しない
- **APIアクセス制御**: 認証必須にする
- **レスポンスフィルタ**: シリアライザでホワイトリスト方式のフィールド制御
