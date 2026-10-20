
import json
from datetime import datetime, timezone
from scanner import scan_requirements


def classify_severity(vulnerability):
    aliases = vulnerability.get("aliases", [])
    summary = vulnerability.get("summary", "").lower()

    # CVSS scoring will be added in the next upgrade.
    # Do not guess severity from a vulnerability's name.
    return {
        "severity": "UNKNOWN",
        "reason": "Verify the advisory's official CVSS score",
        "aliases": aliases,
        "summary": summary
    }


def main():
    print("DependencyGuard - Security Report")
    print("=" * 45)

    results = scan_requirements()
    total_packages = len(results)
    total_vulnerabilities = 0

    for package in results:
        findings = package.get("findings", [])

        if isinstance(findings, list):
            total_vulnerabilities += len(findings)

    report = {
        "tool": "DependencyGuard",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "packages_scanned": total_packages,
        "vulnerabilities_found": total_vulnerabilities,
        "results": results
    }

    with open(
        "security-report.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(report, file, indent=2)

    print(f"Packages scanned: {total_packages}")
    print(f"Vulnerabilities found: {total_vulnerabilities}")
    print("Report saved: security-report.json")

    for package in results:
        print(f"\nPackage: {package.get('package', 'Unknown')}")
        print(f"Version: {package.get('version', 'Unknown')}")

        findings = package.get("findings", [])

        if isinstance(findings, dict) and "error" in findings:
            print(f"Scan error: {findings['error']}")
            continue

        if not findings:
            print("Status: No vulnerabilities returned by OSV")

        for finding in findings:
            print(f"ID: {finding.get('id', 'Unknown')}")
            print(f"Summary: {finding.get('summary', 'Unavailable')}")
            print("Severity: UNKNOWN (verify official advisory)")


if __name__ == "__main__":
    main()
