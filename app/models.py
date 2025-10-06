from datetime import datetime
from app import db

class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(256), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)
    raw_xml = db.Column(db.Text, nullable=True)  # optional: keep xml for debugging

    hosts = db.relationship("Host", backref="scan", cascade="all, delete-orphan")

class Host(db.Model):
    __tablename__ = "hosts"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    ip = db.Column(db.String(64), nullable=False)
    hostname = db.Column(db.String(256), nullable=True)

    services = db.relationship("Service", backref="host", cascade="all, delete-orphan")

class Service(db.Model):
    __tablename__ = "services"
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(16), nullable=False)
    state = db.Column(db.String(32), nullable=True)
    service_name = db.Column(db.String(128), nullable=True)
    product = db.Column(db.String(256), nullable=True)
    version = db.Column(db.String(128), nullable=True)
