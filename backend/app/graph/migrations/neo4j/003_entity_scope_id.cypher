CREATE INDEX entity_scope_id IF NOT EXISTS FOR (n:Entity) ON (n.tenant_id, n.revision, n.id);
