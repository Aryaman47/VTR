from functools import wraps
import hmac
from flask import Blueprint, request, redirect, url_for, render_template, current_app, flash, session
from app import db
from app.models import Scan, Host, Service, VulnerabilityFinding
from app.scan_queue import enqueue_scan_job
from datetime import datetime
from ipaddress import ip_address, ip_network
import threading
import time
import re

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


def _is_authenticated():
    return bool(session.get("authenticated"))


def _validate_csrf_or_redirect(fallback_endpoint, **fallback_values):
    expected = session.get("csrf_token")
    supplied = request.form.get("csrf_token")

    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        flash("Invalid CSRF token", "danger")
        return redirect(url_for(fallback_endpoint, **fallback_values))
    return None


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if _is_authenticated():
            return view_func(*args, **kwargs)
        flash("Please sign in to continue", "danger")
        return redirect(url_for("main.login", next=request.path))

    return wrapper


@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if _is_authenticated():
            return redirect(url_for("main.home"))
        return render_template("login.html")

    csrf_redirect = _validate_csrf_or_redirect("main.login")
    if csrf_redirect:
        return csrf_redirect

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    expected_username = current_app.config.get("VTR_ADMIN_USERNAME", "admin")
    expected_password = current_app.config.get("VTR_ADMIN_PASSWORD", "admin123")

    if hmac.compare_digest(username, expected_username) and hmac.compare_digest(password, expected_password):
        session["authenticated"] = True
        flash("Signed in successfully", "success")
        next_path = request.args.get("next") or request.form.get("next")
        if not next_path or not next_path.startswith("/"):
            next_path = url_for("main.home")
        return redirect(next_path)

    flash("Invalid username or password", "danger")
    return redirect(url_for("main.login"))


@main.route("/logout", methods=["POST"])
@login_required
def logout():
    csrf_redirect = _validate_csrf_or_redirect("main.home")
    if csrf_redirect:
        return csrf_redirect

    session.pop("authenticated", None)
    flash("Signed out", "success")
    return redirect(url_for("main.login"))

@main.route("/", methods=["GET", "POST"])
@login_required
def home():
    """
    Home page acts as the scanning UI:
    - GET: show scan form + recent scans
    - POST: queue a scan, store status, redirect to report
    """
    if request.method == "GET":
        # fetch recent scans (latest 10)
        recent = Scan.query.order_by(Scan.started_at.desc()).limit(10).all()
        requested_scan_id = request.args.get("scan_id", type=int)

        preferred_scan_id = None
        if requested_scan_id is not None:
            requested_scan = Scan.query.get(requested_scan_id)
            if requested_scan is not None:
                preferred_scan_id = requested_scan.id

        if preferred_scan_id is None:
            for s in recent:
                if _scan_status(s) in {"queued", "running"}:
                    preferred_scan_id = s.id
                    break

        if preferred_scan_id is None:
            for s in recent:
                if _scan_status(s) == "completed":
                    preferred_scan_id = s.id
                    break

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
        return render_template(
            "home.html",
            recent_scans=recent_list,
            preferred_scan_id=preferred_scan_id,
        )

    # POST -> trigger scan (form submission)
    csrf_redirect = _validate_csrf_or_redirect("main.home")
    if csrf_redirect:
        return csrf_redirect

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

    queue_result = enqueue_scan_job(scan.id, target, current_app._get_current_object())
    if queue_result.get("backend") == "rq" and queue_result.get("job_id"):
        scan.raw_xml = f"STATUS:QUEUED\nJOB:{queue_result['job_id']}"
        db.session.add(scan)
        db.session.commit()

    flash(f"Scan #{scan.id} queued for target {target}", "success")

    return redirect(url_for("main.report", scan_id=scan.id))


@main.route("/report/<int:scan_id>")
@login_required
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
@login_required
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
@login_required
def update_finding_status(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    csrf_redirect = _validate_csrf_or_redirect("main.report", scan_id=finding.scan_id)
    if csrf_redirect:
        return csrf_redirect

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
