SHOW PROCEDURES YIELD name
WHERE name IN ['apoc.path.expandConfig', 'apoc.meta.schema', 'gds.pageRank.stream']
RETURN name;
