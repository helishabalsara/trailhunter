# TrailHunter – AWS Cloud Telemetry & Detection Engine

A Python-based AWS CloudTrail telemetry ingestion and threat detection engine that baselines account activity and fires detection rules to surface adversarial behavior.

## Features
- Ingest and normalize CloudTrail logs (S3 or live CloudTrail API)
- Baseline account activity and API call patterns per identity
- YAML-defined detection rules with threshold tuning
- False-positive reduction via behavioral baselining
- JSON structured alerts output

## Architecture
```
CloudTrail Logs (S3 / API)
        │
   [ Ingestor ]       ← boto3, pulls & parses raw events
        │
   [ Normalizer ]     ← flattens nested CloudTrail JSON
        │
   [ Baseliner ]      ← builds per-user/role API baselines
        │
   [ Detector ]       ← evaluates YAML rules against events
        │
   [ Alert Output ]   ← JSON alerts to stdout / file
```

## Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

### Configure AWS credentials
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```
Or use an IAM role / AWS profile.

### Run
```bash
# Ingest from S3 bucket
python main.py --source s3 --bucket your-cloudtrail-bucket --prefix AWSLogs/

# Ingest from local JSON log files
python main.py --source local --path ./sample_logs/

# Run with custom rules directory
python main.py --source local --path ./sample_logs/ --rules ./trailhunter/rules/
```

## Detection Rules
Rules live in `trailhunter/rules/rules.yaml`. Each rule specifies:
```yaml
- id: TH-001
  name: Root Account Usage
  description: Detects any API call made by the root account
  condition:
    field: userIdentity.type
    operator: equals
    value: Root
  severity: critical
```

## Project Structure
```
TrailHunter/
├── main.py                    # Entry point
├── requirements.txt
├── config.yaml                # AWS / output configuration
├── trailhunter/
│   ├── ingestor.py            # CloudTrail log ingestion
│   ├── normalizer.py          # Event normalization
│   ├── baseliner.py           # Activity baselining
│   ├── detector.py            # Rule evaluation engine
│   └── rules/
│       └── rules.yaml         # Detection rules
├── sample_logs/               # Sample CloudTrail JSON for testing
│   └── sample_cloudtrail.json
└── tests/
    └── test_detector.py
```

## Sample Alert Output
```json
{
  "alert_id": "TH-001",
  "rule_name": "Root Account Usage",
  "severity": "critical",
  "timestamp": "2024-11-15T10:23:01Z",
  "actor": "root",
  "source_ip": "1.2.3.4",
  "event_name": "ConsoleLogin",
  "raw_event": { ... }
}
```

## IAM Permissions Required
```json
{
  "Effect": "Allow",
  "Action": [
    "cloudtrail:LookupEvents",
    "s3:GetObject",
    "s3:ListBucket"
  ],
  "Resource": "*"
}
```
