# Vulnerable App

脆弱性診断の学習用やられアプリ（Flask）

IPA「安全なウェブサイトの作り方」およびOWASP Top 10に準拠した10種類の脆弱性を体験できます。

## 実装されている脆弱性

| # | 脆弱性名 | OWASP 2021 | ルート |
|---|---------|------------|--------|
| 1 | XSS（クロスサイトスクリプティング） | A03:Injection | `/vuln/xss` |
| 2 | SQLインジェクション | A03:Injection | `/vuln/sqli` |
| 3 | CSRF（クロスサイトリクエストフォージェリ） | A01:Access Control | `/vuln/csrf` |
| 4 | 認証の不備 | A07:Auth Failures | `/vuln/auth` |
| 5 | 機密情報の露出 | A02:Cryptographic Failures | `/vuln/exposure` |
| 6 | OSコマンドインジェクション | A03:Injection | `/vuln/cmdi` |
| 7 | セキュリティ設定ミス | A05:Misconfiguration | `/vuln/misconfig` |
| 8 | ディレクトリトラバーサル | A01:Access Control | `/vuln/traversal` |
| 9 | アクセス制御の不備 | A01:Access Control | `/vuln/access` |
| 10 | オープンリダイレクト | A01:Access Control | `/vuln/redirect` |

## セットアップ

### 前提
- VirtualBox がインストール済みであること
- Vagrant がインストール済みであること

### VM 起動

```bash
git clone <このリポジトリのURL>
cd vulnerable-app
vagrant up
```

初回起動時に Docker / Docker Compose が自動でインストールされる。

### アプリ起動

```bash
vagrant ssh
cd /vagrant
docker compose up --build -d
```

`http://192.168.56.10:5000` でアクセスできる（Kali VM など同じホストオンリーネットワーク上のマシンから）。

### Docker のみで起動（Vagrant不要）

```bash
docker compose up --build -d
```

`http://localhost:5000` でアクセスできる。

### アプリ停止

```bash
vagrant ssh
cd /vagrant
docker compose down
```

### VM 停止 / 破棄

```bash
vagrant halt     # VM を停止
vagrant destroy  # VM を破棄
```

## テスト用アカウント

| ユーザー名 | パスワード | ロール |
|-----------|-----------|--------|
| admin | admin123 | admin |
| user1 | password | user |
| user2 | letmein | user |
| tanaka | tanaka2024 | user |

## 使い方

1. ダッシュボード（`/`）から各脆弱性ページに遷移
2. 各ページの「体験」セクションで脆弱性を実際に試す
3. 「ヒント」セクションで段階的にヒントを確認
4. `solutions/` ディレクトリに各脆弱性の詳細な解説と対策を記載

### データベースのリセット

SQLインジェクション等でデータが壊れた場合は、ナビバーの「DB初期化」ボタンまたは `/reset-db` にアクセスしてリセットできます。

## 注意事項

このアプリケーションは学習目的で意図的に脆弱性を含んでいます。本番環境やインターネットに公開しないでください。
