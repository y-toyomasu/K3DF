# K3DF

K3DF (K3 Defender Lab) は、Webアプリケーションの脆弱性を安全な検証環境で学ぶためのラボです。\
意図的に SQL インジェクションの脆弱性を含む Flask アプリケーションと、その挙動を確認するシンプルなスキャナーを提供します。

> [!WARNING]
> このプロジェクトは学習・検証専用です。脆弱なアプリケーションを含むため、インターネットへ公開したり、本番環境で使用したりしないでください。スキャナーは、自分が所有または明示的な許可を得た環境だけを対象に実行してください。

## 構成

```text
.
├── compose.yaml       # WebアプリケーションとNginxのコンテナ定義
├── web/               # 意図的に脆弱なFlaskアプリケーション
├── dashboard/         # 防御状況を可視化する独立アプリ
├── scanner/           # SQLインジェクション検証用スキャナー
├── nginx/             # リバースプロキシ設定
├── data/              # 学習用SQLiteデータベース
└── logs/              # Nginxログの出力先
```

## 前提条件

- Docker Engine
- Docker Compose

Raspberry Pi 上で環境を準備する場合は、[K3Defnder-K3Atacker-infra](https://github.com/y-toyomasu/K3Defnder-K3Atacker-infra) を利用できます。

## 起動

```bash
docker compose up --build -d
```

開発時は `env.example` を `.env` としてコピーし、`environment=dev` を設定します。`web/app.py` はコンテナへ共有され、変更時に Flask が自動で再起動します。

```bash
docker-compose up --build
```

起動後、次のURLにアクセスします。

- アプリケーション: `http://localhost/`
- ヘルスチェック: `http://localhost/health`
- 顧客データの例: `http://localhost/customer?id=1`
- 防御状況ダッシュボード: `http://localhost:8888/`

停止するには、以下を実行します。

```bash
docker compose down
```

## スキャナー

アプリケーションの起動後、許可されたローカル環境に対して実行します。

```bash
python3 scanner/scanner.py http://localhost
```

スキャナーは `/customer` エンドポイントに対して通常リクエストと検証用リクエストを送り、応答差分から SQL インジェクションの可能性をJSON形式で出力します。

## ログ

Nginx のアクセスログとエラーログは、以下に保存されます。

```text
logs/nginx/access.log
logs/nginx/error.log
```

## 防御状況ダッシュボード

K3DF は防御側の状況だけを扱います。独立した `dashboard` サービスが TCP ポート `8888` で稼働し、5 秒ごとに次を更新して可視化します。

- Web サーバーのヘルスチェックと応答時間
- 直近 200 件の Nginx リクエスト、クライアント数、最多アクセス先
- 4xx/5xx 応答数
- SQL インジェクションの兆候となるリクエスト（`UNION SELECT`、常に真になる比較、コメント記号など）の件数と直近イベント

通常の到達性確認（`/health`、`/`）や未公開パスへの 404 は、疑わしいリクエストとしては数えません。検知は学習環境のログを補助的に可視化するためのもので、WAF や侵入検知システムの代替ではありません。

攻撃側のステータスおよび操作履歴は、K3AT リポジトリで管理します。

## ライセンス

[MIT License](LICENSE)
