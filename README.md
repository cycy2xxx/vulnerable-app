# Vulnerable App

脆弱性診断の学習用やられアプリ（Flask）

## セットアップ

### 前提
- Docker / Docker Compose がインストール済みであること

### 起動

```bash
git clone <このリポジトリのURL>
cd vulnerable-app
docker compose up --build -d
```

`http://<VMのIP>:5000` でアクセスできる。

### 停止

```bash
docker compose down
```
