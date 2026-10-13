SELECT json_group_array(json_object('table', name, 'columns', json(columns), 'indexes', json(indexes), 'foreignKeys', json(foreign_keys)))
FROM (
 SELECT m.name,
  (SELECT json_group_array(json_object('name', name, 'type', type, 'required', "notnull", 'default', dflt_value, 'primaryKey', pk)) FROM (SELECT * FROM pragma_table_info(m.name) ORDER BY name)) AS columns,
  (SELECT json_group_array(json_object('name', name, 'unique', "unique", 'columns', json(columns))) FROM (SELECT i.name, i."unique", (SELECT json_group_array(name) FROM (SELECT name FROM pragma_index_info(i.name) ORDER BY seqno)) AS columns FROM pragma_index_list(m.name) i ORDER BY i.name)) AS indexes,
  (SELECT json_group_array(json_object('table', "table", 'from', "from", 'to', "to", 'onDelete', on_delete, 'onUpdate', on_update)) FROM (SELECT * FROM pragma_foreign_key_list(m.name) ORDER BY "from", "table", "to")) AS foreign_keys
 FROM sqlite_master m WHERE type = 'table' AND name NOT LIKE 'better_auth_%' AND name NOT LIKE 'sqlite_%' ORDER BY name
)
