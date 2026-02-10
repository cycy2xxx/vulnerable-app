# 2. SQLインジェクション

## 概要
ユーザーの入力値がSQL文に直接埋め込まれることで、攻撃者が任意のSQLクエリを実行できる脆弱性。認証バイパス、データ窃取、データの改ざん・削除が可能。

## 参考
- IPA「安全なウェブサイトの作り方」: 1.1 SQLインジェクション
- OWASP Top 10 2021: A03:2021 – Injection
- CWE-89: SQL Injection

## 脆弱なコード

```python
@app.route('/vuln/sqli', methods=['GET', 'POST'])
def vuln_sqli():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    # f-stringでSQL文を組み立て（脆弱）
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    rows = conn.execute(query).fetchall()
```

## 攻撃手順とペイロード例

### 認証バイパス
- ユーザー名: `admin' --`
- パスワード: （何でもOK）
- 生成されるSQL: `SELECT * FROM users WHERE username = 'admin' --' AND password = '...'`
- `--` 以降がコメントアウトされ、パスワードチェックが無効化される

### 全ユーザー取得
- ユーザー名: `' OR '1'='1`
- パスワード: `' OR '1'='1`
- 条件が常にTRUEとなり、全ユーザーが返される

### UNION SELECT によるデータ抽出
- ユーザー名: `' UNION SELECT 1,username,password,email,role,credit_card,secret_note FROM users --`
- 別クエリの結果を結合して取得

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/app.py` | 107 | `f"SELECT * FROM users WHERE username = '{username}' ..."` — f-stringでSQL組み立て |
| `app/app.py` | 109 | `conn.execute(query).fetchall()` — 組み立てたクエリをそのまま実行 |
| `app/app.py` | 114-115 | `except Exception as e: error = f'SQLエラー: {e}'` — エラーメッセージがそのまま表示される（情報漏洩） |

比較として安全な実装（同ファイル内）:
| `app/app.py` | 52-55 | `login()` ではプレースホルダ `?` を使用（安全） |

### コードレビューで探すパターン（grep対象）
```bash
# f-string / format() / % でSQLを組み立てている箇所
grep -rn 'f"SELECT\|f"INSERT\|f"UPDATE\|f"DELETE' app/
grep -rn '\.format(.*SELECT\|\.format(.*INSERT' app/
grep -rn '% .*SELECT\|% .*INSERT' app/

# 文字列結合でSQLを組み立てている箇所
grep -rn 'execute.*+.*request\|execute.*+.*form' app/

# .execute() にプレースホルダ (?) がない箇所
grep -rn '\.execute(' app/ | grep -v '?'

# SQLエラーをユーザーに返している箇所
grep -rn 'SQLエラー\|sql.*error\|Exception.*sql' app/
```

### 診断の勘所
1. **SQL文の組み立て方法**: f-string / `.format()` / `%` / 文字列結合は全て危険。プレースホルダ (`?` や `%s`) のみ安全
2. **全ての `.execute()` 呼び出しを確認**: 第2引数にパラメータタプルが渡されているか
3. **エラーハンドリング**: SQLエラーの詳細がユーザーに表示されると、テーブル名やカラム名が漏洩する（エラーベースSQLi）
4. **ORM使用状況**: 生SQLを使っている箇所が特にリスクが高い
5. **同一ファイル内の比較**: `login()`（L52: 安全）と `vuln_sqli()`（L107: 危険）を比較すると、違いが明確になる

## 対策（修正コード + セキュリティ原則）

### 修正方法: パラメータ化クエリ（プレースホルダ）
```python
@app.route('/vuln/sqli', methods=['GET', 'POST'])
def vuln_sqli():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    # プレースホルダを使用（安全）
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    rows = conn.execute(query, (username, password)).fetchall()
```

### セキュリティ原則
- **パラメータ化クエリ**: SQL文とデータを分離する（最も効果的な対策）
- **最小権限**: DBユーザーに必要最小限の権限のみ付与する
- **入力値検証**: ホワイトリスト方式でバリデーションする
- **エラーメッセージ**: 詳細なSQLエラーをユーザーに表示しない
