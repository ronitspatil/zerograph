CREATE CONSTRAINT entity_key IF NOT EXISTS FOR (n:Entity) REQUIRE n.key IS UNIQUE;
CREATE CONSTRAINT snapshot_key IF NOT EXISTS FOR (s:Snapshot) REQUIRE s.key IS UNIQUE;
CREATE INDEX entity_scope IF NOT EXISTS FOR (n:Entity) ON (n.tenant_id, n.revision);
CREATE INDEX snapshot_scope IF NOT EXISTS FOR (n:Snapshot) ON (n.tenant_id, n.revision);
CREATE INDEX snapshot_age IF NOT EXISTS FOR (s:Snapshot) ON (s.tenant_id, s.created_at_ms);
