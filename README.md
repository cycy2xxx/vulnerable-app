# Vulnerable App

脆弱性診断の学習用やられアプリ（Flask）

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
