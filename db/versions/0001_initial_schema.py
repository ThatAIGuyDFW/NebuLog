"""Initial schema: events, alerts, alert_rules, sources, audit_log

Revision ID: 0001
Revises:
Create Date: 2026-06-23
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, ARRAY, TEXT

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Extensions ---
    op.execute("CREATE EXTENSION IF NOT EXISTS pgvector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman")
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    # --- Enums ---
    op.execute("""
        CREATE TYPE source_type_enum AS ENUM (
            'fortigate', 'cisco_asa', 'cisco_ios', 'windows', 'linux'
        )
    """)
    op.execute("""
        CREATE TYPE log_level_enum AS ENUM (
            'emergency', 'alert', 'critical', 'error',
            'warning', 'notice', 'info', 'debug'
        )
    """)
    op.execute("""
        CREATE TYPE category_enum AS ENUM (
            'auth', 'network', 'endpoint', 'system', 'threat', 'compliance'
        )
    """)
    op.execute("""
        CREATE TYPE severity_enum AS ENUM (
            'critical', 'high', 'medium', 'low', 'info'
        )
    """)
    op.execute("""
        CREATE TYPE alert_status_enum AS ENUM (
            'open', 'acknowledged', 'closed'
        )
    """)
    op.execute("""
        CREATE TYPE rule_type_enum AS ENUM (
            'threshold', 'sequence', 'absence', 'blacklist', 'anomaly'
        )
    """)

    # --- events (partitioned by received_at, monthly) ---
    op.execute("""
        CREATE TABLE events (
            id              UUID            NOT NULL DEFAULT uuid_generate_v4(),
            received_at     TIMESTAMPTZ     NOT NULL,
            event_time      TIMESTAMPTZ,
            source_host     TEXT            NOT NULL,
            source_type     source_type_enum,
            log_level       log_level_enum,
            category        category_enum,
            action          TEXT,
            src_ip          INET,
            src_port        INTEGER,
            dst_ip          INET,
            dst_port        INTEGER,
            protocol        TEXT,
            user_name       TEXT,
            process_name    TEXT,
            event_id        TEXT,
            message         TEXT            NOT NULL,
            raw_message     TEXT,
            tags            TEXT[],
            geo_country     TEXT,
            geo_city        TEXT,
            alert_id        UUID,
            ingest_node     TEXT,
            raw_hash        TEXT,
            extra           JSONB
        ) PARTITION BY RANGE (received_at)
    """)
    # Default partition to catch anything not matched by a specific month partition
    op.execute("""
        CREATE TABLE events_default PARTITION OF events DEFAULT
    """)
    # Index on the parent table — inherited by partitions
    op.execute("CREATE INDEX idx_events_received_at ON events (received_at)")
    op.execute("CREATE INDEX idx_events_source_host ON events (source_host)")
    op.execute("CREATE INDEX idx_events_src_ip ON events (src_ip)")
    op.execute("CREATE INDEX idx_events_category ON events (category)")
    op.execute("CREATE INDEX idx_events_alert_id ON events (alert_id)")

    # --- sources ---
    op.create_table(
        "sources",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("ip_address", INET, nullable=False, unique=True),
        sa.Column("hostname", TEXT),
        sa.Column("source_type", sa.Enum("fortigate", "cisco_asa", "cisco_ios", "windows", "linux", name="source_type_enum", create_type=False), nullable=False),
        sa.Column("label", TEXT),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True)),
        sa.Column("event_rate_1m", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )

    # --- alert_rules ---
    op.create_table(
        "alert_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("name", TEXT, nullable=False),
        sa.Column("description", TEXT),
        sa.Column("rule_type", sa.Enum("threshold", "sequence", "absence", "blacklist", "anomaly", name="rule_type_enum", create_type=False), nullable=False),
        sa.Column("severity", sa.Enum("critical", "high", "medium", "low", "info", name="severity_enum", create_type=False), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("body", JSONB, nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )

    # --- alerts ---
    op.create_table(
        "alerts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("rule_id", UUID(as_uuid=True), sa.ForeignKey("alert_rules.id"), nullable=False),
        sa.Column("severity", sa.Enum("critical", "high", "medium", "low", "info", name="severity_enum", create_type=False), nullable=False),
        sa.Column("status", sa.Enum("open", "acknowledged", "closed", name="alert_status_enum", create_type=False), nullable=False, server_default="'open'"),
        sa.Column("title", TEXT, nullable=False),
        sa.Column("description", TEXT),
        sa.Column("src_ip", TEXT),
        sa.Column("source_host", TEXT),
        sa.Column("first_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("assigned_to", TEXT),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("extra", JSONB),
    )
    op.create_index("idx_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("idx_alerts_status", "alerts", ["status"])
    op.create_index("idx_alerts_severity", "alerts", ["severity"])

    # --- audit_log ---
    op.create_table(
        "audit_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("user_email", TEXT),
        sa.Column("action", TEXT, nullable=False),
        sa.Column("resource_type", TEXT),
        sa.Column("resource_id", TEXT),
        sa.Column("source_ip", TEXT),
        sa.Column("request_body", JSONB),
        sa.Column("response_status", sa.Integer),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_audit_log_created_at", "audit_log", ["created_at"])
    op.create_index("idx_audit_log_user_email", "audit_log", ["user_email"])

    # --- Seed default correlation rules (Section 12) ---
    op.execute("""
        INSERT INTO alert_rules (name, description, rule_type, severity, body) VALUES
        (
            'Brute Force Login', 'Five or more failed logins from the same source IP within 10 minutes',
            'threshold', 'critical',
            '{"filters": {"event_id": ["4625", "ssh_auth_fail"]}, "group_by": "src_ip", "count": 5, "window_seconds": 600}'
        ),
        (
            'Privilege Escalation', 'Privileged logon (Win 4672) outside business hours',
            'threshold', 'high',
            '{"filters": {"event_id": ["4672"], "category": "auth", "action": "privileged_logon"}, "count": 1, "window_seconds": 86400, "outside_hours": {"start": 6, "end": 20}}'
        ),
        (
            'Audit Log Cleared', 'Windows audit log cleared (1102) or FortiGate audit clear event',
            'threshold', 'critical',
            '{"filters": {"event_id": ["1102", "0100044546"]}, "count": 1, "window_seconds": 86400}'
        ),
        (
            'New Service Installed', 'New Windows service installed (Event ID 7045)',
            'threshold', 'high',
            '{"filters": {"event_id": ["7045"]}, "count": 1, "window_seconds": 86400}'
        ),
        (
            'Mass Firewall Denies', 'More than 100 firewall deny events from same source IP within 5 minutes',
            'threshold', 'high',
            '{"filters": {"action": "deny", "source_type": "fortigate"}, "group_by": "src_ip", "count": 100, "window_seconds": 300}'
        ),
        (
            'Admin Login After Hours', 'Admin-group authentication event between 8pm and 6am local time',
            'threshold', 'medium',
            '{"filters": {"category": "auth", "tags": ["admin"]}, "count": 1, "window_seconds": 86400, "outside_hours": {"start": 6, "end": 20}}'
        ),
        (
            'Lateral Movement Sequence', 'Failed login followed by successful login from same source IP within 2 minutes',
            'sequence', 'high',
            '{"steps": [{"event_id": "4625"}, {"event_id": "4624"}], "group_by": "src_ip", "window_seconds": 120}'
        ),
        (
            'PCI Source Silence', 'No events received from any PCI cardholder-environment source within 24 hours',
            'absence', 'high',
            '{"filters": {"tags": ["pci:cardholder_env"]}, "window_seconds": 86400}'
        ),
        (
            'Known Bad IP', 'Any event from an IP in the threat intelligence blocklist',
            'blacklist', 'critical',
            '{"field": "src_ip", "list_name": "threat_intel_blocklist"}'
        ),
        (
            'Outbound Data Exfil', 'Single FortiGate session with more than 500MB of outbound bytes',
            'threshold', 'high',
            '{"filters": {"source_type": "fortigate"}, "aggregate": {"field": "sentbyte", "op": "gt", "value": 524288000}, "window_seconds": 3600}'
        ),
        (
            'Multiple Account Lockouts', 'Three or more different users locked out (4740) within 30 minutes',
            'threshold', 'high',
            '{"filters": {"event_id": ["4740"]}, "distinct_users": 3, "window_seconds": 1800}'
        ),
        (
            'SSH Root Login', 'Successful SSH login as root on any Linux host',
            'threshold', 'critical',
            '{"filters": {"source_type": "linux", "user_name": "root", "action": "logon"}, "count": 1, "window_seconds": 86400}'
        )
    """)


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("alerts")
    op.drop_table("alert_rules")
    op.drop_table("sources")
    op.execute("DROP TABLE IF EXISTS events CASCADE")
    op.execute("DROP TYPE IF EXISTS rule_type_enum")
    op.execute("DROP TYPE IF EXISTS alert_status_enum")
    op.execute("DROP TYPE IF EXISTS severity_enum")
    op.execute("DROP TYPE IF EXISTS category_enum")
    op.execute("DROP TYPE IF EXISTS log_level_enum")
    op.execute("DROP TYPE IF EXISTS source_type_enum")
