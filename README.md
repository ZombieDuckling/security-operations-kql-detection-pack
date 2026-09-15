# Security Operations KQL Detection Pack

A small security operations portfolio project for security-engineer interviews. It contains KQL detections, synthetic log samples, watchlist examples, a workbook skeleton, and tests that validate the detection files are present and mapped to expected security operations tables.

This repo uses synthetic data only. It is not copied from a production tenant and it does not contain private customer or tenant information.

## Skills demonstrated

- security operations analytics-rule thinking
- KQL detection writing
- Entra ID sign-in and audit log investigation
- Defender / endpoint and mailbox incident patterns
- Watchlist-based tuning
- Git-based validation and CI

## Detection coverage

| Detection | security operations table | Scenario |
|---|---|---|
| `impossible-travel.kql` | `SigninLogs` | Same user signs in from distant geographies in a short period |
| `suspicious-oauth-consent.kql` | `AuditLogs` | New app/service principal or high-risk consent activity |
| `admin-role-change.kql` | `AuditLogs` | Privileged role membership changes |
| `mass-download-activity.kql` | `OfficeActivity` | High-volume SharePoint/OneDrive downloads |
| `repeated-failed-signins.kql` | `SigninLogs` | Password spray or repeated failed login behavior |
| `device-isolation-event.kql` | `DeviceEvents` | Defender endpoint isolation actions |
| `mailbox-forwarding-rule.kql` | `OfficeActivity` | Suspicious inbox forwarding or redirect rules |

## How to use

1. Review detections in `detections/`.
2. Adapt table names and fields to your security operations workspace schema.
3. Use `watchlists/privileged-users.csv` and `watchlists/trusted-locations.csv` as examples for tuning.
4. Import or adapt `workbooks/security-operations-overview.workbook.json` as a starting workbook skeleton.
5. Run tests locally:

```bash
python3 tests/validate_pack.py
```

## Interview talking points

- I start with the detection hypothesis, not the query.
- I identify the data source, event fields, time window, false positives and response steps.
- I use watchlists to tune known admin accounts, trusted ranges and VIP users.
- I test detection logic against synthetic data before proposing production deployment.
- I document severity, mapping and triage steps so the detection can be maintained.

## Safe data note

All sample data is synthetic. User names, domains, IPs and events are examples only.
