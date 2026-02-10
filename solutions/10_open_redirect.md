# 10. オープンリダイレクト

## 概要
リダイレクト先のURLを検証せずにそのまま使用することで、攻撃者が用意した外部の悪意あるサイトへユーザーを誘導できる脆弱性。

## 参考
- IPA「安全なウェブサイトの作り方」: 入力値の検証不足
- OWASP Top 10 2021: A01:2021 – Broken Access Control
- CWE-601: URL Redirection to Untrusted Site

## 脆弱なコード

```python
@app.route('/vuln/redirect')
def vuln_redirect():
    url = request.args.get('url', '')
    if url:
        # リダイレクト先の検証なし（脆弱）
        return redirect(url)

# ログイン後のリダイレクトも未検証
@app.route('/login', methods=['GET', 'POST'])
def login():
    if user:
        next_url = request.args.get('next', '/')
        return redirect(next_url)  # 検証なし
```

## 攻撃手順とペイロード例

### 直接的なオープンリダイレクト
```
http://localhost:5000/vuln/redirect?url=https://evil.example.com
```

### ログイン後のリダイレクト悪用
```
http://localhost:5000/login?next=https://evil.example.com/phishing
```
ユーザーがログイン後、フィッシングサイトにリダイレクトされる。

### フィッシング攻撃シナリオ
1. 攻撃者が以下のURLをメールで送信:
   `http://trusted-site.com/vuln/redirect?url=https://evil.example.com/login`
2. 被害者はURLのドメインが信頼できるサイトであることを確認してクリック
3. フィッシングサイト（本物そっくりのログインページ）にリダイレクト
4. 被害者が認証情報を入力 → 攻撃者に窃取される

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/app.py` | 299-302 | `request.args.get('url', '')` → `redirect(url)` — パラメータを未検証でリダイレクト |
| `app/app.py` | 61-62 | `next_url = request.args.get('next', '/')` → `redirect(next_url)` — ログイン後のリダイレクトも未検証 |

### コードレビューで探すパターン（grep対象）
```bash
# redirect() の全使用箇所
grep -rn 'redirect(' app/app.py

# redirect() にユーザー入力が渡される箇所
grep -rn 'redirect(.*request\.\|redirect(.*next\|redirect(.*url\|redirect(.*return_to' app/

# URL検証関数の有無
grep -rn 'urlparse\|is_safe_url\|url_has_allowed_host' app/

# クエリパラメータからURLを取得している箇所
grep -rn "request\.args\.get.*url\|request\.args\.get.*next\|request\.args\.get.*redirect\|request\.args\.get.*return" app/

# Location ヘッダの直接設定
grep -rn 'Location\|headers\[' app/
```

### 診断の勘所
1. **`redirect()` の全数検査**: `redirect()` の引数にユーザー入力が直接渡されていないか、全箇所を確認
2. **リダイレクト先パラメータの特定**: `url`, `next`, `redirect`, `return_to`, `continue` などの名前で外部入力を受け取っていないか
3. **URL検証ロジック**: `urlparse()` 等でスキーム・ホストを検証しているか。相対パスのみ許可しているか
4. **ログイン後のリダイレクト**: OAuth / ログインフローの `next` パラメータは見落としやすいポイント
5. **JavaScript内のリダイレクト**: `window.location = ユーザー入力` パターンもチェック（DOMベースのオープンリダイレクト）
6. **プロトコル相対URL**: `//evil.com` のような `//` で始まるURLがブロックされるか

## 対策（修正コード + セキュリティ原則）

### 修正方法: URL検証
```python
from urllib.parse import urlparse

def is_safe_url(url):
    """リダイレクト先が安全（同一ホスト内）かどうかを検証"""
    if not url:
        return False
    parsed = urlparse(url)
    # スキームが空（相対パス）またはホストが空であれば安全
    return parsed.scheme == '' and parsed.netloc == ''

@app.route('/vuln/redirect')
def vuln_redirect():
    url = request.args.get('url', '')
    if url and is_safe_url(url):
        return redirect(url)
    return redirect('/')  # 安全でないURLの場合はトップへ

@app.route('/login', methods=['GET', 'POST'])
def login():
    if user:
        next_url = request.args.get('next', '/')
        if not is_safe_url(next_url):
            next_url = '/'
        return redirect(next_url)
```

### セキュリティ原則
- **ホワイトリスト方式**: 許可するリダイレクト先をリスト化
- **相対パスのみ許可**: 外部URLへのリダイレクトを拒否
- **URL解析**: `urlparse()` でスキームとホストを検証
- **警告ページ**: 外部サイトへのリダイレクト時は確認画面を表示
