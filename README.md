# secure-telemetry-stream

Streaming pipeline and API layer over zero-trust security telemetry: synthetic web-proxy, firewall and DNS transaction logs from users, devices and branch sites, processed at scale with Kafka + Flink, anomaly detection and cross-signal correlation, served over REST and gRPC.

## Architecture

```
 users/devices/branch sites (synthetic)
            |
            v
 +-------------------+      telemetry.{proxy,dns,firewall}      +----------------------+
 | Java load         |  key=tenant (tenant partitioning)        | Apache Flink job     |
 | generator         +----------------------------------------->| event time, watermarks|
 | (injectable       |        Apache Kafka                      | dedup (keyed state)  |
 |  attacks)         |                                          | EWMA + robust z-score|
 +-------------------+                                          | rules, windows       |
                                                                | correlation -> 1     |
                                                                | incident + confidence|
                                                                +----+-----------+-----+
                                                                     |           |
                                          exactly-once Kafka sink    v           v
                                                          telemetry.incidents  ClickHouse
                                                                               (DuckDB fallback)
                                                                     |           |
                                                                     v           v
                                                                Redis hot-path cache
                                                                     |
                                                            +--------+---------+
                                                            | Go API service   |
                                                            | REST /v1 /v2     |
                                                            | gRPC + streaming |
                                                            | JWT tenant auth  |
                                                            +--------+---------+
                                                                     |
                                                   Prometheus / Grafana / OpenTelemetry traces
```

## Design

| Concern | Choice | Why |
|---|---|---|
| Transport | Kafka topics `telemetry.{proxy,dns,firewall}`, key = tenant | Tenant partitioning, ordering per tenant, replay |
| Processing | Flink DataStream, event time, 30s bounded out-of-orderness, checkpointing 10s, exactly-once transactional Kafka sink | Correct late data, no duplicate incidents |
| Same logic in tests | Pure-Java in-process runner (`sts.Pipeline`) with identical operators | Fast JUnit/benchmark without a Flink cluster; Flink source is complete in `flink-job/` |
| Detection | Robust z-score (median/MAD) + EWMA per `tenant|user`, plus rules | Robust to outliers, cheap per-entity state |
| Correlation | Per-user buffer (10 min): alerts from proxy/DNS/firewall collapse to one incident, confidence 0.75–0.97 | One incident per attack, not one per event |
| Storage | ClickHouse (MergeTree, partitioned by tenant) via HTTP JSONEachRow; DuckDB view over the same JSONL for local tests | Columnar analytics without a cluster locally |
| Hot path | Redis cache (RESP, 5s TTL) with in-process fallback | Incident reads are the hot API path |
| API | Go, REST (OpenAPI 3, `/v1` + `/v2` envelope) and gRPC (proto3, server-streaming incidents) | Versioned contracts, both checked by contract tests against the running server |
| Auth | HS256 JWT, `tenant` claim enforced on REST and gRPC; per-tenant rate limit | Tenant-scoped zero-trust access |
| Backpressure | Idempotent Kafka producer, bounded buffer + `max.block.ms`; consumer lag via consumer groups / Prometheus | Block, never drop, and measure lag under burst |
| Observability | Prometheus metrics, Grafana dashboard JSON, `traceparent` (OpenTelemetry) propagation | Metrics/traces without SDK lock-in in the demo |

## Attacks injected (labeled, for precision/recall)

Credential stuffing · DNS tunneling · data-exfiltration bursts · impossible travel — see `Generator` in `pipeline/src/main/java/sts/Generator.java`.

## Run

```bash
make run                 # docker compose: Kafka, Flink, ClickHouse, Redis, API, Prometheus, Grafana
# load data:
cd pipeline && mvn -q package && java -cp target/pipeline-1.0.0.jar sts.LoadGenerator kafka:9092 100000
# token + query:
curl "localhost:8080/v1/token?tenant=tenant-1"
curl -H "Authorization: Bearer <token>" "localhost:8080/v1/incidents?tenant=tenant-1"
curl -H "Authorization: Bearer <token>" "localhost:8080/v2/events?limit=10"
```

Local (no Docker): `cd pipeline && mvn test`, `cd api && go test ./...`, API serves seeded data on `:8080` (REST) and `:50051` (gRPC); set `STS_DATA_FILE=data/events.jsonl` to serve pipeline output.

## Test

```bash
make test        # JUnit (pipeline + detectors) and Go tests (API + OpenAPI/proto contract tests)
```

## Benchmark

```bash
make bench       # EVENTS=200000 default; writes bench-results.txt
```

### Results (Apple M5 Pro, in-process runner, 200,428 events incl. 428 labeled attack events)

| Metric | Value |
|---|---|
| Throughput | **62,735 events/sec** |
| End-to-end latency p50 / p99 | **0.015 ms / 0.033 ms** per event (in-process) |
| Consumer lag under burst | **200,428 max → drained to 0** |
| API latency REST / gRPC | **0.028 ms / 0.107 ms** per op (loopback single-op, `go test -bench`) |
| Detection: credential stuffing | precision **1.00**, recall **1.00** |
| Detection: DNS tunneling | precision **1.00**, recall **1.00** |
| Detection: data exfiltration | precision **1.00**, recall **1.00** |
| Detection: impossible travel | precision **1.00**, recall **1.00** |

Raw output (`make bench` → `bench-results.txt`):

```
events=200428 processed=200428 deduped=0 incidents=16
throughput_events_per_sec=62735
e2e_latency_p50_ms=0.015 p99_ms=0.033 (in-process per-event)
consumer_lag_burst_max=200428 drained_to=0
detection[credential_stuffing] precision=1.00 recall=1.00 (tp=4 pred=4 truth=4)
detection[dns_tunneling] precision=1.00 recall=1.00 (tp=4 pred=4 truth=4)
detection[data_exfiltration] precision=1.00 recall=1.00 (tp=4 pred=4 truth=4)
detection[impossible_travel] precision=1.00 recall=1.00 (tp=4 pred=4 truth=4)
BenchmarkREST  28280 ns/op
BenchmarkGRPC 107054 ns/op
```

Synthetic attacks are deliberately separable, hence 1.00 precision/recall on this generator; the value is in the labeled evaluation harness, not the score.

## Layout

`pipeline/` Java 21 generator + detectors + in-process runner + benchmark · `flink-job/` Flink job · `api/` Go REST/gRPC service (+ `proto/`, `openapi.yaml`, generated `pb/`) · `store/` ClickHouse/DuckDB schemas · `observability/` Prometheus + Grafana · `k8s/` manifests + Helm chart · `docker-compose.yml`

## License

MIT — see `LICENSE`.
