# Kibana Dashboard Setup — Step by Step

## After ELK is running (http://localhost:5601)

### Step 1: Create Index Pattern
1. Left menu → Stack Management
2. Kibana → Index Patterns → Create index pattern
3. Pattern: `websec-tester-*`
4. Timestamp: `@timestamp`
5. Save

### Step 2: Create Dashboard
1. Left menu → Dashboard → Create new dashboard
2. Add the following panels:

---

### Panel 1: Scan Results Summary (Metric)
- Visualization: Metric
- Field: `scan.pipeline_summary.confirmed_vulns`
- Label: "Total Confirmed Vulnerabilities"

### Panel 2: Verified vs Confirmed (Bar Chart)
- Visualization: Vertical Bar
- X-axis: `scan.target_url.keyword`
- Y-axis 1: `scan.pipeline_summary.confirmed_vulns` (avg)
- Y-axis 2: `scan.pipeline_summary.sandbox_verified` (avg)
- Label: "Confirmed vs Verified by Target"

### Panel 3: Risk Level Distribution (Pie)
- Visualization: Pie
- Field: `scan.report.overall_risk.keyword`
- Shows: LOW / MEDIUM / HIGH / CRITICAL distribution

### Panel 4: Scan Timeline (Line)
- Visualization: Line
- X-axis: `@timestamp` (date histogram, 1 hour)
- Y-axis: Count
- Label: "Scan Activity Over Time"

### Panel 5: Critique Approved Rate (Gauge)
- Visualization: Gauge
- Formula: `scan.pipeline_summary.critique_approved / scan.pipeline_summary.execution_steps`
- Range: 0-1

### Panel 6: Live Event Stream (Data Table)
- Visualization: Data Table
- Columns: timestamp, target_url, vuln_type, verdict, severity
- Sort: @timestamp DESC
- Shows real-time findings as they happen

---

## For Demo Presentation

1. Start your scan: `python main.py --target http://localhost:9001/WebGoat --mode full`
2. Switch to Kibana → Discover
3. Set time filter: Last 15 minutes
4. Enable auto-refresh: 5 seconds
5. New events appear as the pipeline runs

Say during demo:
"As each agent completes its stage, structured logs are streamed into
 the ELK stack via Filebeat. Kibana visualizes findings in real time,
 providing SIEM-style monitoring of the autonomous penetration test."
