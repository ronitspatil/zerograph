CALL mg.procedures() YIELD name
WHERE name IN ['pagerank.get', 'path.expand', 'nxalg.shortest_path']
RETURN name;
