FROM python:3.11-slim

# 作業ディレクトリの設定
WORKDIR /app

# OSコマンドインジェクション演習用ツールのインストール
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping net-tools curl && rm -rf /var/lib/apt/lists/*

# 依存ライブラリのインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ソースコードのコピー
COPY . .

EXPOSE 5000

# Flaskの起動（app.pyを動かす）
CMD ["python", "app.py"]
