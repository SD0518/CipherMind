title: "Analyze Mordor logs for suspicious activity"
description: "Run the LLM-assisted log analyzer: reads Mordor JSON events line-by-line, finds suspicious events, maps to MITRE ATT&CK techniques and returns mitigation suggestions."
steps:
  - "Open .windsurf/context.md summary"
  - "Run `python self_learn\nathan\agents\analyze_mordor.py --input ./nathan/mordor_dataset_test/*.json --output ./nathan/reports/report.json`"
  - "If threats found, generate short human summary & mitigation recommendations in `./nathan/reports/summary.md`"
