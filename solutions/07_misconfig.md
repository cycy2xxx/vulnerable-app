# 7. セキュリティ設定ミス

## 概要
デバッグモードの有効化、秘密鍵のハードコード、ディレクトリリスティング、デフォルト認証情報の使用など、本番環境での設定不備。

## 参考
- IPA「安全なウェブサイトの作り方」: 設定管理の不備
- OWASP Top 10 2021: A05:2021 – Security Misconfiguration
- CWE-215: Insertion of Sensitive Information Into Debugging Code

## 脆弱なコード

```python
# ハードコードされた秘密鍵
app.secret_key = 'super-secret-key-123'

# デバッグモード有効
app.run(host='0.0.0.0', port=5000, debug=True)

# ディレクトリリスティング
@app.route('/files/')
def directory_listing(filename=''):
    files = os.listdir(data_dir)
    # ファイル一覧を表示
```

## 攻撃手順とペイロード例

### Werkzeugデバッガの悪用
1. `/console` にアクセス
2. Pythonコードを実行:
```python
import os
os.popen('id').read()
os.popen('cat /etc/passwd').read()
```

### ディレクトリリスティング
- `/files/` にアクセスしてファイル一覧を確認
- 機密ファイル（secret_data.txt）を発見・ダウンロード

### 秘密鍵の悪用
秘密鍵がわかれば、Flaskのセッションを偽造できる:
```bash
pip install flask-unsign
flask-unsign --sign --cookie "{'user_id': 1, 'role': 'admin'}" --secret 'super-secret-key-123'
```

### デフォルト認証情報
- admin / admin123 でログイン

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/app.py` | 20 | `app.secret_key = 'super-secret-key-123'` — 秘密鍵がハードコード |
| `app/app.py` | 310 | `app.run(... debug=True)` — デバッグモード有効（Werkzeugデバッガが動く） |
| `app/app.py` | 230-238 | `/files/` ルート — ディレクトリ内のファイル一覧を表示 |
| `app/init_db.py` | 28 | `'admin', 'admin123'` — デフォルト認証情報 |
| `app/Dockerfile` | 全体 | セキュリティ設定なし（非rootユーザー未使用、ヘルスチェックなし） |
| `docker-compose.yml` | 6 | `0.0.0.0:5000:5000` — 全インターフェースにバインド |

### コードレビューで探すパターン（grep対象）
```bash
# ハードコードされた秘密鍵・パスワード・トークン
grep -rn 'secret_key\|SECRET_KEY\|password\|PASSWORD\|token\|TOKEN\|api_key' app/ --include='*.py'

# デバッグモードの設定
grep -rn 'debug=True\|DEBUG.*=.*True' app/

# ディレクトリリスティング / ファイル一覧の実装
grep -rn 'os\.listdir\|os\.scandir\|glob\.' app/

# エラーハンドラの有無（カスタムエラーページがないとスタックトレース露出）
grep -rn 'errorhandler\|app\.error' app/

# HTTPS関連設定
grep -rn 'PREFERRED_URL_SCHEME\|ssl_context\|SECURE' app/

# セキュリティヘッダの設定
grep -rn 'X-Frame-Options\|X-Content-Type\|Strict-Transport\|Content-Security-Policy' app/

# requirements.txt の確認（既知の脆弱性があるバージョンか）
cat app/requirements.txt
```

### 診断の勘所
1. **設定値のハードコード**: `secret_key`, パスワード, APIキーがソースコードに直書きされていないか。環境変数や設定ファイルを使うべき
2. **デバッグモード**: `debug=True` は本番で絶対に無効にする。Werkzeugデバッガはリモートコード実行を許す
3. **デフォルト認証情報**: シードデータや設定ファイル内のパスワードが変更されていないか
4. **エラーハンドリング**: カスタムの 404/500 エラーページがないと、スタックトレースが表示される
5. **Dockerの設定**: `Dockerfile` で非rootユーザーを使っているか、不要なツールがインストールされていないか
6. **依存パッケージ**: `requirements.txt` のバージョンに既知のCVEがないか（`pip audit` / `safety check`）
7. **HTTPヘッダ**: セキュリティ関連ヘッダ（CSP, X-Frame-Options等）が設定されているか

## 対策（修正コード + セキュリティ原則）

### 修正方法
```python
import os

# 環境変数から秘密鍵を取得
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

# 本番環境ではデバッグモードを無効化
app.run(host='0.0.0.0', port=5000, debug=False)
```

### セキュリティ原則
- **デバッグモード無効化**: 本番環境では必ず `debug=False`
- **秘密鍵の管理**: 環境変数やシークレットマネージャーを使用
- **ディレクトリリスティング無効化**: Webサーバーの設定で無効にする
- **デフォルト認証情報の変更**: 初回セットアップ時に強制変更
- **セキュリティヘッダ**: Server ヘッダからバージョン情報を削除
