CREATE TABLE IF NOT EXISTS alert_incidents (
    alert_uid TEXT PRIMARY KEY,
    sn_sys_id TEXT,
    sn_incident_number TEXT,
    status TEXT,
    updated_at DATETIME DEFAULT CURRENT_YESTERDAY
);