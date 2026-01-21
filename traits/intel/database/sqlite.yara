// Migrated from malcontent: collect/databases/sqlite.yara

rule sqlite: medium {
  meta:
    description = "accesses SQLite databases"
    confidence  = "0.66"

  strings:
$ref  = "sqlite" fullword
    $ref3 = "sqlite3" fullword
  condition:
    any of them
}
