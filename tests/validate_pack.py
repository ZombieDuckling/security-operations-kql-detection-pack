from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS = ROOT / "detections"
REQUIRED = {
    "impossible-travel.kql": "SigninLogs",
    "suspicious-oauth-consent.kql": "AuditLogs",
    "admin-role-change.kql": "AuditLogs",
    "mass-download-activity.kql": "OfficeActivity",
    "repeated-failed-signins.kql": "SigninLogs",
    "device-isolation-event.kql": "DeviceEvents",
    "mailbox-forwarding-rule.kql": "OfficeActivity",
}


def test_detection_inventory_matches_required_mapping():
    expected = set(REQUIRED)
    actual = {path.name for path in DETECTIONS.glob("*.kql")}

    assert actual == expected, (
        "Detection inventory must match REQUIRED mapping. "
        f"Missing from disk: {sorted(expected - actual)}; "
        f"Unmapped files: {sorted(actual - expected)}"
    )


def test_detection_files_exist_and_reference_expected_tables():
    for filename, table in REQUIRED.items():
        path = DETECTIONS / filename
        assert path.exists(), f"Missing {filename}"
        text = path.read_text()
        assert table in text, f"{filename} should reference {table}"
        assert "|" in text, f"{filename} does not look like KQL"


def test_samples_and_watchlists_exist():
    for rel in [
        "samples/signinlogs.csv",
        "samples/auditlogs.csv",
        "samples/officeactivity.csv",
        "watchlists/privileged-users.csv",
        "watchlists/trusted-locations.csv",
        "workbooks/security-operations-overview.workbook.json",
    ]:
        assert (ROOT / rel).exists(), f"Missing {rel}"


if __name__ == "__main__":
    test_detection_inventory_matches_required_mapping()
    test_detection_files_exist_and_reference_expected_tables()
    test_samples_and_watchlists_exist()
    print("security operations KQL detection pack validation passed")
