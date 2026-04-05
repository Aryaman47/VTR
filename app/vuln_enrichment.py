import json
from urllib.parse import urlencode
from urllib.request import Request, urlopen


_NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _severity_from_score(score):
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_cvss_score(cve_payload):
    metrics = (cve_payload or {}).get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key) or []
        if not metric_list:
            continue

        first = metric_list[0] or {}
        data = first.get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, (int, float)):
            return float(score)

    return None


def _extract_description(cve_payload):
    descriptions = (cve_payload or {}).get("descriptions") or []
    if not descriptions:
        return None

    english = [d for d in descriptions if (d or {}).get("lang") == "en"]
    if english:
        return (english[0] or {}).get("value")

    return (descriptions[0] or {}).get("value")


def _nvd_request(url, timeout, api_key=None):
    headers = {"User-Agent": "VTR/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="ignore")
    return json.loads(raw)


def _build_keywords(service_name=None, product=None, version=None):
    keywords = []

    service_name = (service_name or "").strip()
    product = (product or "").strip()
    version = (version or "").strip()

    if product and version:
        keywords.append(f"{product} {version}")
    if product:
        keywords.append(product)
    if service_name and version:
        keywords.append(f"{service_name} {version}")
    if service_name:
        keywords.append(service_name)

    deduped = []
    seen = set()
    for keyword in keywords:
        key = keyword.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(keyword)

    return deduped


def find_cves_for_service(
    service_name=None,
    product=None,
    version=None,
    timeout=10,
    results_per_query=5,
    max_queries=3,
    api_key=None,
):
    keywords = _build_keywords(service_name=service_name, product=product, version=version)
    if not keywords:
        return []

    all_findings = {}

    for keyword in keywords[:max_queries]:
        query = urlencode({"keywordSearch": keyword, "resultsPerPage": results_per_query})
        url = f"{_NVD_CVE_ENDPOINT}?{query}"

        try:
            data = _nvd_request(url, timeout=timeout, api_key=api_key)
        except Exception:
            continue

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue

            score = _extract_cvss_score(cve)
            finding = {
                "cve_id": cve_id,
                "description": _extract_description(cve),
                "cvss_score": score,
                "severity": _severity_from_score(score),
                "source": "nvd",
            }

            existing = all_findings.get(cve_id)
            if not existing:
                all_findings[cve_id] = finding
                continue

            # Keep the higher confidence score if multiple keyword queries return same CVE.
            old_score = existing.get("cvss_score")
            new_score = finding.get("cvss_score")
            if old_score is None and new_score is not None:
                all_findings[cve_id] = finding
            elif isinstance(old_score, (int, float)) and isinstance(new_score, (int, float)) and new_score > old_score:
                all_findings[cve_id] = finding

    findings = list(all_findings.values())
    findings.sort(key=lambda f: (f.get("cvss_score") is None, -(f.get("cvss_score") or 0.0), f.get("cve_id") or ""))
    return findings
