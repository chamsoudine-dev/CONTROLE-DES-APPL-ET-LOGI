-- Métadonnées de synchronisation et appairage.
CREATE TABLE sync_state (
  key   TEXT PRIMARY KEY,   -- ex. "remote_cursor:<device>", "epoch"
  value TEXT NOT NULL
);

CREATE INDEX audit_logs_ts ON audit_logs(ts);
CREATE INDEX licenses_customer ON licenses(customer_id);
