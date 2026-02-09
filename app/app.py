from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def index():
    # 診断用に「外部からの入力」を受け取れる口を作っておく
    name = request.args.get('name', 'Guest')
    return render_template('index.html', name=name)

if __name__ == '__main__':
    # 重要：コンテナ外（Kali）から繋ぐために 0.0.0.0 にする
    app.run(host='0.0.0.0', port=5000, debug=True)