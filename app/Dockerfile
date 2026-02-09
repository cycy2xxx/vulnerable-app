FROM python:3.11-slim

# 作業ディレクトリの設定
WORKDIR /app

# 依存ライブラリのインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ソースコードのコピー
COPY . .

EXPOSE 5000

# Flaskの起動（app.pyを動かす）
CMD ["python", "app.py"]