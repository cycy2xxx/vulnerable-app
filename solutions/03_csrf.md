# 3. CSRF（クロスサイトリクエストフォージェリ）

## 概要
Webアプリケーションがリクエストの送信元を検証しない場合、攻撃者が用意した罠サイトからユーザーの意図しないリクエストを送信させることができる脆弱性。

## 参考
- IPA「安全なウェブサイトの作り方」: 1.6 CSRF
- OWASP Top 10 2021: A01:2021 – Broken Access Control
- CWE-352: Cross-Site Request Forgery

## 脆弱なコード

```python
@app.route('/vuln/csrf', methods=['GET', 'POST'])
def vuln_csrf():
    if request.method == 'POST':
        to = request.form.get('to', '')
        amount = int(request.form.get('amount', 0))
        # CSRFトークンの検証がない
        session['balance'] -= amount
        message = f'{to} に ¥{amount:,} を送金しました。'
```

```html
<!-- フォームにCSRFトークンがない -->
<form method="POST">
    <input type="text" name="to">
    <input type="number" name="amount">
    <button type="submit">送金する</button>
</form>
```

## 攻撃手順とペイロード例

### 攻撃用HTML（罠ページ）
```html
<html>
<body>
  <h1>おめでとうございます！当選しました！</h1>
  <form id="csrf" action="http://localhost:5000/vuln/csrf"
        method="POST" style="display:none">
    <input name="to" value="attacker">
    <input name="amount" value="50000">
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

被害者がこのページを開くと、自動的に送金リクエストが送信される。

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/app.py` | 124-141 | `vuln_csrf()` — POSTリクエストでCSRFトークンを検証していない |
| `app/app.py` | 130-138 | `request.form` から直接取得して残高を変更（リクエスト元の検証なし） |
| `app/templates/vuln_csrf.html` | フォーム部分 | `<form method="POST">` にCSRFトークンの hidden input がない |
| `app/app.py` | 19 | `app.secret_key` がハードコード — セッションの偽造リスク |

### コードレビューで探すパターン（grep対象）
```bash
# CSRFトークンなしでPOSTを受け付けるルート
grep -rn "methods=.*POST" app/app.py

# テンプレートのフォームでcsrf_tokenが含まれていないもの
grep -rn '<form.*method.*POST' app/templates/ | while read line; do
  file=$(echo "$line" | cut -d: -f1)
  grep -L 'csrf_token' "$file"
done

# Flask-WTF等のCSRF保護ライブラリの有無
grep -rn 'CSRFProtect\|csrf_token\|WTF' app/

# SameSite Cookie設定の有無
grep -rn 'SESSION_COOKIE_SAMESITE\|samesite' app/
```

### 診断の勘所
1. **状態変更を伴う全POSTエンドポイントを列挙**: 各フォームにCSRFトークンがあるか確認
2. **CSRFライブラリの導入有無**: Flask-WTF等が `requirements.txt` に含まれているか
3. **Cookieの設定**: `SESSION_COOKIE_SAMESITE`, `SESSION_COOKIE_HTTPONLY` の設定を確認
4. **Referer/Originヘッダの検証**: サーバー側でリクエスト元を検証しているか
5. **GETでの状態変更**: GETリクエストで副作用のある処理（`/reset-db` 等）がないかも確認

## 対策（修正コード + セキュリティ原則）

### 修正方法: CSRFトークンの導入
```python
# Flask-WTFを使用
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

```html
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>
```

### セキュリティ原則
- **CSRFトークン**: フォームに一意のトークンを含め、サーバー側で検証する
- **SameSite Cookie**: `SameSite=Lax` または `Strict` を設定する
- **Refererヘッダ検証**: リクエスト元のドメインを検証する
- **重要な操作の再認証**: 送金等の重要操作時にパスワード再入力を求める
