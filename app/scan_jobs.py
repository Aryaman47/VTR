from datetime import datetime
import os

from app import create_app, db
from app.models import Host, Scan, Service, VulnerabilityFinding
from app.scanner.nmap_parser import parse_nmap_xml, run_nmap_and_get_xml
from app.vuln_enrichment import find_cves_for_service


def run_scan_job(scan_id, target):
    app = create_app()
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
                        version=svc.get("version"),
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

                    for finding in cve_cache.get(service_fingerprint, []):
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

            scan.finished_at = datetime.utcnow()
            db.session.add(scan)
            db.session.commit()

        except Exception as exc:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.finished_at = datetime.utcnow()
                scan.raw_xml = (scan.raw_xml or "") + f"\n\nERROR: {str(exc)}"
                db.session.add(scan)
                db.session.commit()
            app.logger.exception("Scan failed for target %s", target)

        finally:
            try:
                if xml_path and os.path.exists(xml_path):
                    os.remove(xml_path)
            except Exception:
                app.logger.warning("Failed to remove temporary nmap XML file: %s", xml_path)