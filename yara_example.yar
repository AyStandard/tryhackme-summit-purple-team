rule suspicious_sample_behavior {
  meta:
    author = "Shobande Wariz Ayobami"
    description = "Detects behavior patterns similar to sample.exe"
  strings:
    $a = "UnusualPersistenceCall"
  condition:
    $a
}
