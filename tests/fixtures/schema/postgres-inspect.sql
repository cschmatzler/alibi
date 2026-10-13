SELECT COALESCE(jsonb_agg(jsonb_build_object('table', name, 'columns', columns, 'indexes', indexes, 'foreignKeys', foreign_keys) ORDER BY name), '[]'::jsonb)::text
FROM (
 SELECT t.relname AS name,
  (SELECT jsonb_agg(jsonb_build_object('name', a.attname, 'type', format_type(a.atttypid, a.atttypmod), 'required', a.attnotnull, 'default', pg_get_expr(d.adbin, d.adrelid), 'primaryKey', EXISTS(SELECT 1 FROM pg_constraint p WHERE p.conrelid = t.oid AND p.contype = 'p' AND a.attnum = ANY(p.conkey))) ORDER BY a.attname) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = t.oid AND d.adnum = a.attnum WHERE a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped) AS columns,
  (SELECT COALESCE(jsonb_agg(jsonb_build_object('name', i.relname, 'unique', x.indisunique, 'columns', (SELECT jsonb_agg(a.attname ORDER BY k.ordinality) FROM unnest(x.indkey) WITH ORDINALITY k(attnum, ordinality) JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum)) ORDER BY i.relname), '[]'::jsonb) FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid WHERE x.indrelid = t.oid) AS indexes,
  (SELECT COALESCE(jsonb_agg(pg_get_constraintdef(c.oid) ORDER BY pg_get_constraintdef(c.oid)), '[]'::jsonb) FROM pg_constraint c WHERE c.conrelid = t.oid AND c.contype = 'f') AS foreign_keys
 FROM pg_class t JOIN pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = CURRENT_SCHEMA() AND t.relkind = 'r' AND t.relname NOT LIKE 'better_auth_%'
) tables
