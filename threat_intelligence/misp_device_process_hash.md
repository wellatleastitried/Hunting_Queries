# Detect Malicious Binary from MISP Intel

## Description
This query searches binaries that have been executed and compares them to file hashes pulled from MISP threat intelligence.

## Sentinel
```kql
let daysago = now(-7d)
ThreatIntelIndicators
| where SourceSystem == "MISP"
| where TimeGenerated > daysago
| where IsActive == true
| where ObservableKey == "file:hashes.'SHA256'"
| extend FileHash = ObservableValue
| join kind=inner(
    DeviceProcessEvents
    | where TimeGenerated > daysago
    | where ActionType == "ProcessCreated"
    | where isnotempty(SHA256)
    | extend BinaryHash = SHA256
) on $left.FileHash == $right.BinaryHash
```
