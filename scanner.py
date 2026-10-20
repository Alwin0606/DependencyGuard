
import requests
from packaging.version import Version, InvalidVersion

OSV_API = "https://api.osv.dev/v1/query"


def scan_package(name, version):
    payload = {
        "package": {
            "name": name,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        response = requests.post(
            OSV_API,
            json=payload,
            timeout=15
        )
        response.raise_for_status()

        vulnerabilities = response.json().get("vulns", [])
        unique = {}

        for vuln in vulnerabilities:
            aliases = sorted(set(vuln.get("aliases", [])))
            identifiers = [vuln.get("id", "Unknown")] + aliases

            # Merge entries sharing a known vulnerability identifier.
            existing_key = next(
                (identifier for identifier in identifiers
                 if identifier in unique),
                None
            )

            key = existing_key or (
                aliases[0] if aliases else identifiers[0]
            )

            if key in unique:
                existing = unique[key]
                existing["aliases"] = sorted(
                    set(existing["aliases"] + aliases)
                )

                if (
                    existing["summary"] == "No summary available"
                    and vuln.get("summary")
                ):
                    existing["summary"] = vuln["summary"]
            else:
                unique[key] = {
                    "id": vuln.get("id", "Unknown"),
                    "summary": vuln.get(
                        "summary"
                    ) or "No summary available",
                    "aliases": aliases
                }

        return list(unique.values())

    except requests.RequestException as error:
        return {"error": str(error)}


def scan_requirements(filename="requirements.txt"):
    results = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "==" not in line:
                results.append({
                    "requirement": line,
                    "error": "Use an exact version, e.g. package==1.2.3"
                })
                continue

            name, version = line.split("==", 1)
            name = name.strip()
            version = version.strip()

            try:
                Version(version)
            except InvalidVersion:
                results.append({
                    "package": name,
                    "error": f"Invalid version: {version}"
                })
                continue

            findings = scan_package(name, version)

            results.append({
                "package": name,
                "version": version,
                "findings": findings,
                "vulnerability_count": (
                    len(findings)
                    if isinstance(findings, list)
                    else None
                )
            })

    return results
