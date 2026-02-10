# 8. ディレクトリトラバーサル

## 概要
ファイルパスにユーザー入力をそのまま使用し、`../` などのパストラバーサル文字列を検証しないことで、意図しないディレクトリのファイルが読み取られる脆弱性。

## 参考
- IPA「安全なウェブサイトの作り方」: 1.3 ディレクトリ・トラバーサル
- OWASP Top 10 2021: A01:2021 – Broken Access Control
- CWE-22: Path Traversal

## 脆弱なコード

```python
@app.route('/vuln/traversal')
def vuln_traversal():
    filename = request.args.get('file', '')
    # パス検証なし（脆弱）
    filepath = os.path.join(app.root_path, 'data', filename)
    with open(filepath, 'r') as f:
        content = f.read()
```

## 攻撃手順とペイロード例

### アプリケーションソースコードの読み取り
```
/vuln/traversal?file=../app.py
/vuln/traversal?file=../init_db.py
```

### システムファイルの読み取り
```
/vuln/traversal?file=../../etc/passwd
/vuln/traversal?file=../../etc/hostname
/vuln/traversal?file=../../proc/self/environ
```

### 秘密鍵やDB情報の取得
```
/vuln/traversal?file=../vulnerable.db
```

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/app.py` | 246 | `filename = request.args.get('file', '')` — ユーザー入力をファイル名として使用 |
| `app/app.py` | 251 | `os.path.join(app.root_path, 'data', filename)` — パス結合後の検証がない |
| `app/app.py` | 253 | `open(filepath, 'r')` — 検証なしでファイルをオープン |

比較として安全な実装（同ファイル内）:
| `app/app.py` | 234-235 | `directory_listing()` では `send_from_directory()` を使用（Flaskが内部でパス検証） |

### コードレビューで探すパターン（grep対象）
```bash
# ファイル操作でユーザー入力を使用している箇所
grep -rn 'open(\|os\.path\.join' app/ | grep -v '__pycache__'

# os.path.join にユーザー入力が渡される箇所
grep -rn 'os\.path\.join.*request\|os\.path\.join.*filename\|os\.path\.join.*file' app/

# パス検証関数の使用有無
grep -rn 'os\.path\.realpath\|os\.path\.abspath\|os\.path\.normpath' app/
grep -rn 'secure_filename\|send_from_directory' app/

# ファイル読み書き操作の一覧
grep -rn 'open(\|read(\|write(\|send_file\|send_from_directory' app/

# パストラバーサル文字列の検証
grep -rn '\.\.\|\.\./' app/app.py
```

### 診断の勘所
1. **ファイル操作の全数検査**: `open()`, `os.path.join()`, `send_file()` 等の呼び出しを全て列挙
2. **入力→ファイルパスの追跡**: `request.args` / `request.form` の値がファイルパスに使われる経路を追跡
3. **パス正規化の有無**: `os.path.realpath()` や `os.path.abspath()` で正規化した上で、ベースディレクトリ内かチェックしているか
4. **フレームワーク機能の活用**: `send_from_directory()` は内部でトラバーサル防止を行うが、`open()` は何もしない
5. **同一ファイル内の比較**: `directory_listing()`（L234: `send_from_directory` で安全）と `vuln_traversal()`（L251: `open()` で危険）を比較
6. **NULLバイト**: 古いPythonでは `%00` でファイル拡張子チェックをバイパスできた（現在のPythonでは修正済み）

## 対策（修正コード + セキュリティ原則）

### 修正方法: パスの正規化と検証
```python
@app.route('/vuln/traversal')
def vuln_traversal():
    filename = request.args.get('file', '')
    data_dir = os.path.join(app.root_path, 'data')
    filepath = os.path.realpath(os.path.join(data_dir, filename))

    # 正規化されたパスが許可されたディレクトリ内か検証
    if not filepath.startswith(os.path.realpath(data_dir)):
        return 'Access denied', 403

    with open(filepath, 'r') as f:
        content = f.read()
```

### 修正方法2: Flaskのsend_from_directory
```python
from flask import send_from_directory

@app.route('/vuln/traversal')
def vuln_traversal():
    filename = request.args.get('file', '')
    # send_from_directory は内部でパストラバーサルを検証する
    return send_from_directory('data', filename)
```

### セキュリティ原則
- **パスの正規化**: `os.path.realpath()` でシンボリックリンクも解決
- **ベースディレクトリの検証**: 正規化後のパスが許可範囲内かチェック
- **ファイル名のバリデーション**: `../` やNULLバイトを拒否
- **最小権限**: アプリケーションユーザーの読み取り権限を制限
