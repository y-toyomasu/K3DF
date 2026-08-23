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

Defender に Scanner の結果を渡す場合は、共有状態ディレクトリへ最新結果を書き出します。

```bash
K3DF_SCANNER_RESULT_PATH=state/scanner/latest.json python3 scanner/scanner.py http://localhost
```

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

## Defender Architecture

`defender` サービスは、アプリケーションとは別に動作する軽量な防御Agentです。Nginx access log、Scanner結果、Defender Action結果を Evidence として正規化し、次のループを実行します。

```text
Observe → Evidence Collection → Evidence Filtering → Evidence Batch
→ Kimi Reasoning → Capability / Exposure Update → Defense Scenario
→ Local Policy → Containment / Investigation → Verification → State Update
```

Evidence は `K3DF_REASONING_INTERVAL_SEC`（初期値10秒）ごとにまとめます。新しい Evidence がなければ Kimi API は呼び出しません。これはリクエストごとのAPI呼び出しを避け、Pi 2上のリソース消費とAPI利用量を抑えつつ、関連するアクセスを1つの文脈として分析するためです。

### Evidence Filtering と Deduplication

`K3DF_IGNORE_NETWORKS` にはカンマ区切りでCIDRを指定できます。初期値の `10.8.8.0/24` は信頼ネットワークとして、Threat Evidence、Incident、Capability推定、Scenario、BAN候補、Kimi Contextから除外されます。生ログは保持し、`EVIDENCE_IGNORED` イベントとメトリクスだけを残します。

同じ送信元・メソッド・エンドポイント・パラメータ名・応答コードの Evidence は、Batch内で `count`、`first_seen`、`last_seen` を持つ1件に集約します。Kimiには最大50件の正規化Evidence、アクティブなScanner finding、最大10件の未解決仮説とWatch Conditionだけを渡します。

### Kimi Reasoning と Local Policy

Kimi K3は提案だけを返します。APIキーは `MOONSHOT_API_KEY`、API互換エンドポイントは `https://api.moonshot.ai/v1`、モデルは `kimi-k3` を使い、`K3DF_REASONING_EFFORT` の初期値は `low` です。キー未設定、通信失敗、JSON形式不正は `ERROR` イベントとして記録し、Defenderは停止しません。

KimiへのContextには、現在のThreat Level、Incident、推定Capability、Exposure Graph、許可済みDefender Capability、バッチEvidence、Scanner finding、Watch Conditionを含めます。例として、SQL InjectionのEvidenceから `parameter_discovery` や `application_data_read` を `suspected`/`likely`/`confirmed` として推定し、`/customer → id → SQL Injection → customer_database` をExposure Graphへ追加できます。

Scenarioは `DETECT`、`INVESTIGATE`、`CONTAIN`、`REMEDIATE`、`VERIFY` の候補として保存しますが、実行前に必ずLocal Policyで `ALLOW`、`CONDITIONAL`、`BLOCK` を判定します。任意shell、任意ファイル削除、外部ネットワーク操作、SSH変更は許可しません。

### Nginx IP Block Safety

許可された `block_ip(ip, duration, reason)` は、Defenderの永続ブロックリストに短時間だけ登録します。Nginxは各リクエストでDefenderの内部認可エンドポイントを確認し、登録済みIPへ `403` を返します。ホストのfirewall、Dockerソケット、任意コマンドは使用しません。

localhost、Docker系プライベートネットワーク、management network、Ignore Network、allowlistはすべてBAN不可です。実行後はブロックリストの存在と有効期限を検証し、`ACTION` と `VERIFY` のイベントを残します。

### State persistence と Dashboard interface

`state/defender_state.json` は原子的な置換で保存する現在スナップショットです。Threat Level、推定Attack Capability、Exposure Graph、Incident、Scenario、Watch Condition、ブロック済みIP、メトリクスを含みます。`state/events.ndjson` は追記専用のイベント履歴で、Evidence、Reasoning、Policy、Action、Verification、Errorを記録します。

DashboardはDefenderのPython moduleをimportせず、このJSON/NDJSONを読み取り専用で参照します。侵入度は固定整数ではなく、CapabilityとExposure GraphからDashboard側で派生表示します。MITRE ATT&CKは分析Contextとして記録するのみで、固定的な防御フェーズや時系列としては扱いません。

Defenderの実行ログでは、`K3DF PLAN cycle=... evidence=... window=...` がBatch推論の開始、`K3DF SUMMARY` が成功、`K3DF ANALYSIS ... safe_failure` が安全に終了した失敗を示します。

## ライセンス

[MIT License](LICENSE)
