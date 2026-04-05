from flask import Blueprint, request, redirect, url_for, render_template, current_app, flash
from app import db
from app.models import Scan, Host, Service, VulnerabilityFinding
from app.scanner.nmap_parser import run_nmap_and_get_xml, parse_nmap_xml
from app.vuln_enrichment import find_cves_for_service
from datetime import datetime
from ipaddress import ip_address, ip_network
import threading
import time
import re
import os

main = Blueprint("main", __name__)


_HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

_CRITICAL_PORTS = {23, 445}
_HIGH_PORTS = {21, 22, 3389, 5900, 3306, 5432, 6379, 27017}
_CRITICAL_SERVICES = {"telnet", "smb", "microsoft-ds", "netbios-ssn"}
_HIGH_SERVICES = {"ftp", "ssh", "rdp", "vnc", "mysql", "postgresql", "redis", "mongodb"}

_RATE_LIMIT_BUCKETS = {}
_RATE_LIMIT_LOCK = threading.Lock()
_FINDING_STATUSES = {"new", "triaged", "in_progress", "resolved", "risk_accepted", "false_positive"}


def _normalize_target(target):
    if not target:
        return None

    candidate = target.strip()
    if len(candidate) > 253:
        return None

    if any(char in candidate for char in [" ", "\t", "\n", "\r", ";", "&", "|", "$", "<", ">", "`", "\\"]):
        return None

    try:
        ip_address(candidate)
        return candidate
    except ValueError:
        pass

    try:
        ip_network(candidate, strict=False)
        return candidate
    except ValueError:
        pass

    if _HOSTNAME_PATTERN.fullmatch(candidate):
        return candidate

    return None


def _rate_limited(client_id):
    if not client_id:
        client_id = "unknown"

    now = time.time()
    window = current_app.config.get("SCAN_RATE_LIMIT_WINDOW_SECONDS", 60)
    max_requests = current_app.config.get("SCAN_RATE_LIMIT_MAX_REQUESTS", 5)

    with _RATE_LIMIT_LOCK:
        bucket = _RATE_LIMIT_BUCKETS.get(client_id, [])
        bucket = [ts for ts in bucket if now - ts <= window]

        if len(bucket) >= max_requests:
            _RATE_LIMIT_BUCKETS[client_id] = bucket
            return True

        bucket.append(now)
        _RATE_LIMIT_BUCKETS[client_id] = bucket
        return False


def _classify_service_severity(service):
    state = (service.get("state") or "").lower()
    if state != "open":
        return "low"

    port = service.get("port") or 0
    service_name = (service.get("service_name") or service.get("service") or "").lower()

    if port in _CRITICAL_PORTS or service_name in _CRITICAL_SERVICES:
        return "critical"
    if port in _HIGH_PORTS or service_name in _HIGH_SERVICES:
        return "high"
    if port > 0:
        return "medium"
    return "low"


def _scan_status(scan):
    raw_xml = scan.raw_xml or ""
    if scan.finished_at is None:
        if raw_xml.startswith("STATUS:RUNNING"):
            return "running"
        return "queued"
    if "\n\nERROR:" in raw_xml or raw_xml.startswith("ERROR:"):
        return "failed"
    return "completed"


def _scan_error(scan):
    raw_xml = scan.raw_xml or ""
    marker = "ERROR:"
    idx = raw_xml.rfind(marker)
    if idx == -1:
        return None
    return raw_xml[idx + len(marker):].strip() or "Unknown scan error"


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


def _run_scan_job(app, scan_id, target):
    xml_path = None
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        scan.raw_xml = "STATUS:RUNNING"
        db.session.add(scan)
        db.session.commit()

        try:
            xml_path, xml_text = run_nmap_and_get_xml(target, extra_args=None, timeout=300)

            scan.raw_xml = xml_text
            scan.finished_at = datetime.utcnow()
            db.session.add(scan)
            db.session.commit()

            parsed = parse_nmap_xml(xml_text)
            cve_cache = {}
            cve_enabled = app.config.get("CVE_ENRICHMENT_ENABLED", True)
            nvd_timeout = app.config.get("NVD_API_TIMEOUT_SECONDS", 10)
            nvd_results = app.config.get("NVD_RESULTS_PER_QUERY", 5)
            nvd_max_queries = app.config.get("NVD_MAX_QUERIES_PER_SERVICE", 3)
            nvd_api_key = app.config.get("NVD_API_KEY")

            for h in parsed:
                host = Host(scan_id=scan.id, ip=h.get("ip"), hostname=h.get("hostname"))
                db.session.add(host)
                db.session.flush()

                for svc in h.get("services", []):
                    service = Service(
                        host_id=host.id,
                        port=svc.get("port") or 0,
                        protocol=svc.get("protocol") or "",
                        state=svc.get("state"),
                        service_name=svc.get("service_name"),
                        product=svc.get("product"),
                        version=svc.get("version")
                    )
                    db.session.add(service)
                    db.session.flush()

                    if not cve_enabled:
                        continue

                    service_fingerprint = "|".join(
                        [
                            (svc.get("service_name") or "").strip().lower(),
                            (svc.get("product") or "").strip().lower(),
                            (svc.get("version") or "").strip().lower(),
                        ]
                    )

                    if service_fingerprint not in cve_cache:
                        cve_cache[service_fingerprint] = find_cves_for_service(
                            service_name=svc.get("service_name"),
                            product=svc.get("product"),
                            version=svc.get("version"),
                            timeout=nvd_timeout,
                            results_per_query=nvd_results,
                            max_queries=nvd_max_queries,
                            api_key=nvd_api_key,
                        )

                    findings = cve_cache.get(service_fingerprint, [])
                    for finding in findings:
                        vf = VulnerabilityFinding(
                            scan_id=scan.id,
                            host_id=host.id,
                            service_id=service.id,
                            cve_id=finding.get("cve_id") or "UNKNOWN",
                            description=finding.get("description"),
                            cvss_score=finding.get("cvss_score"),
                            severity=finding.get("severity") or "unknown",
                            source=finding.get("source") or "nvd",
                            status="new",
                            first_seen_at=datetime.utcnow(),
                            last_seen_at=datetime.utcnow(),
                        )
                        db.session.add(vf)

            db.session.commit()

        except Exception as e:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.finished_at = datetime.utcnow()
                scan.raw_xml = (scan.raw_xml or "") + f"\n\nERROR: {str(e)}"
                db.session.add(scan)
                db.session.commit()
            app.logger.exception("Scan failed for target %s", target)

        finally:
            try:
                if xml_path and os.path.exists(xml_path):
                    os.remove(xml_path)
            except Exception:
                app.logger.warning("Failed to remove temporary nmap XML file: %s", xml_path)

@main.route("/", methods=["GET", "POST"])
def home():
    """
    Home page acts as the scanning UI:
    - GET: show scan form + recent scans
    - POST: run a scan (synchronously), store results, redirect to report
    """
    if request.method == "GET":
        # fetch recent scans (latest 10)
        recent = Scan.query.order_by(Scan.started_at.desc()).limit(10).all()
        recent_list = [
            {
                "id": s.id,
                "target": s.target,
                "started_at": s.started_at,
                "finished_at": s.finished_at,
                "status": _scan_status(s)
            }
            for s in recent
        ]
        return render_template("home.html", recent_scans=recent_list)

    # POST -> trigger scan (form submission)
    client_id = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    if _rate_limited(client_id):
        current_app.logger.warning("Rate limit hit for client %s", client_id)
        flash("Rate limit exceeded. Please wait and try again.", "danger")
        return redirect(url_for("main.home"))

    target = request.form.get("target") or request.form.get("targets")
    target = _normalize_target(target)
    if not target:
        current_app.logger.warning("Rejected invalid scan target from client %s", client_id)
        flash("Invalid target provided", "danger")
        return redirect(url_for("main.home"))

    current_app.logger.info("Accepted scan request from client %s for target %s", client_id, target)

    scan = Scan(target=target, started_at=datetime.utcnow())
    scan.raw_xml = "STATUS:QUEUED"
    db.session.add(scan)
    db.session.commit()

    app_obj = current_app._get_current_object()
    worker = threading.Thread(target=_run_scan_job, args=(app_obj, scan.id, target), daemon=True)
    worker.start()
    flash(f"Scan #{scan.id} queued for target {target}", "success")

    return redirect(url_for("main.report", scan_id=scan.id))


@main.route("/report/<int:scan_id>")
def report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    status = _scan_status(scan)
    error_message = _scan_error(scan)

    hosts = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    finding_counts_by_status = {}

    findings_by_service_id = {}
    for finding in scan.findings:
        findings_by_service_id.setdefault(finding.service_id, []).append(finding)
        finding_status = (finding.status or "new").lower()
        finding_counts_by_status[finding_status] = finding_counts_by_status.get(finding_status, 0) + 1

        sev = (finding.severity or "unknown").lower()
        if sev not in counts:
            sev = "unknown"
        counts[sev] += 1

    for h in scan.hosts:
        host_services = []
        host_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for s in h.services:
            service_findings = findings_by_service_id.get(s.id, [])

            service_severity = _classify_service_severity(
                {
                    "port": s.port,
                    "state": s.state,
                    "service": s.service_name,
                }
            )

            if service_findings:
                scored = [f.cvss_score for f in service_findings if f.cvss_score is not None]
                best_score = max(scored) if scored else None
                service_severity = _severity_from_score(best_score)

                host_counts[service_severity if service_severity in host_counts else "unknown"] += 1
            else:
                host_counts[service_severity] += 1

            host_services.append(
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "state": s.state,
                    "service": s.service_name,
                    "product": s.product,
                    "version": s.version,
                    "severity": service_severity,
                    "findings": [
                        {
                            "id": f.id,
                            "cve_id": f.cve_id,
                            "cvss_score": f.cvss_score,
                            "severity": f.severity,
                            "status": f.status,
                            "source": f.source,
                            "description": f.description,
                        }
                        for f in service_findings
                    ],
                }
            )

        hosts.append({
            "ip": h.ip,
            "hostname": h.hostname,
            "services": host_services,
            "counts": host_counts,
        })

    return render_template(
        "report.html",
        scan=scan,
        hosts=hosts,
        counts=counts,
        status=status,
        error_message=error_message,
        finding_counts_by_status=finding_counts_by_status,
    )


@main.route("/scan/<int:scan_id>/status")
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return {
        "id": scan.id,
        "status": _scan_status(scan),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "error": _scan_error(scan),
    }


@main.route("/finding/<int:finding_id>/status", methods=["POST"])
def update_finding_status(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    next_status = (request.form.get("status") or "").strip().lower()

    if next_status not in _FINDING_STATUSES:
        flash("Invalid finding status", "danger")
        return redirect(url_for("main.report", scan_id=finding.scan_id))

    finding.status = next_status
    finding.last_seen_at = datetime.utcnow()
    db.session.add(finding)
    db.session.commit()

    flash(f"Updated {finding.cve_id} to status '{next_status}'", "success")
    return redirect(url_for("main.report", scan_id=finding.scan_id))
