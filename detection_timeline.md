# Detection Timeline (Redacted)

| Sample | Detection Method | Tool / Rule | Timestamp | Result |
|---------|------------------|--------------|------------|--------|
| sample1.exe | YARA rule | suspicious_sample_behavior | 14:32 | ✅ Flag captured |
| sample2.exe | SIEM query | Suspicious Child Process | 14:45 | ✅ Flag captured |
| sample3.exe | Sigma rule | explorer_child_cmd | 15:10 | ✅ Flag captured |
| sample4.exe | EDR alert | persistence_registry_write | 15:42 | ✅ Flag captured |
| sample5.exe | Correlation rule | multi-stage_detection | 16:12 | ✅ Flag captured |
| Sphinx | Composite detection | multi-layer validation | 16:45 | 🏁 Final flag |
