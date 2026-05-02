# ELK Stack — AI-Powered Web Security Tester SIEM Integration

## Quick Start (Windows with Docker Desktop)

```powershell
# 1. Start Docker Desktop first

# 2. From this folder:
cd elk-docker
docker-compose up -d

# 3. Wait ~60 seconds for all containers to start

# 4. Open Kibana
start http://localhost:5601
```

## What Gets Indexed

| Source | Index Pattern | Description |
|--------|--------------|-------------|
| `reports/*_elk.json` | websec-tester-* | Per-scan ELK reports |
| `reports/benchmark_*.json` | websec-tester-* | Benchmark results |
| `reports/live_events.ndjson` | websec-tester-* | Live events during scan |

## Create Kibana Index Pattern

1. Go to → Stack Management → Index Patterns
2. Create: `websec-tester-*`
3. Time field: `@timestamp`

## Suggested Dashboard Panels

| Panel | Field | Chart Type |
|-------|-------|------------|
| Vulnerability types | `scan.report.overall_risk` | Pie |
| Confirmed vs Verified | `scan.pipeline_summary.confirmed_vulns` | Bar |
| Scan timeline | `@timestamp` | Line |
| False positive rate | `scan.pipeline_summary.false_positive_rate` | Gauge |

## Enable Live Events During Scan

The pipeline writes to `reports/live_events.ndjson` automatically.
Open Kibana → Discover → set refresh every 5s to see live updates.

## Stop ELK

```powershell
docker-compose down
```

## Troubleshooting

- Elasticsearch needs ~2GB RAM — ensure Docker Desktop has 4GB allocated
- If Kibana shows "Unable to connect", wait 60 more seconds
- Check containers: `docker-compose ps`
- View logs: `docker-compose logs filebeat`
