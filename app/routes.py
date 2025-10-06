from flask import Blueprint, request, redirect, url_for, render_template, current_app, flash
from app import db
from app.models import Scan, Host, Service
from app.scanner.nmap_parser import run_nmap_and_get_xml, parse_nmap_xml
from datetime import datetime
import os

main = Blueprint("main", __name__)

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
                "finished_at": s.finished_at
            }
            for s in recent
        ]
        return render_template("home.html", recent_scans=recent_list)

    # POST -> trigger scan (form submission)
    target = request.form.get("target") or request.form.get("targets")
    if not target:
        flash("No target provided", "danger")
        return redirect(url_for("main.home"))

    scan = Scan(target=target, started_at=datetime.utcnow())
    db.session.add(scan)
    db.session.commit()

    xml_path = None
    try:
        xml_path, xml_text = run_nmap_and_get_xml(target, extra_args=None, timeout=300)
        scan.raw_xml = xml_text
        scan.finished_at = datetime.utcnow()
        db.session.add(scan)
        db.session.commit()

        parsed = parse_nmap_xml(xml_text)
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

        db.session.commit()

    except Exception as e:
        scan.finished_at = datetime.utcnow()
        scan.raw_xml = (scan.raw_xml or "") + f"\n\nERROR: {str(e)}"
        db.session.add(scan)
        db.session.commit()
        # show error page
        return render_template("scan_error.html", error=str(e))

    finally:
        try:
            if xml_path and os.path.exists(xml_path):
                os.remove(xml_path)
        except Exception:
            pass

    return redirect(url_for("main.report", scan_id=scan.id))


@main.route("/report/<int:scan_id>")
def report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    hosts = []
    for h in scan.hosts:
        hosts.append({
            "ip": h.ip,
            "hostname": h.hostname,
            "services": [
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "state": s.state,
                    "service": s.service_name,
                    "product": s.product,
                    "version": s.version
                }
                for s in h.services
            ]
        })

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    return render_template("report.html", scan=scan, hosts=hosts, counts=counts)
