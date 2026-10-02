CREATE CONSTRAINT ON (n:Entity) ASSERT n.key IS UNIQUE;
CREATE CONSTRAINT ON (s:Snapshot) ASSERT s.key IS UNIQUE;
CREATE INDEX ON :Entity(key);
CREATE INDEX ON :Entity(tenant_id);
CREATE INDEX ON :Entity(revision);
CREATE INDEX ON :Snapshot(tenant_id);
CREATE INDEX ON :Snapshot(created_at_ms);
