// Migrated from malcontent: collect/databases/postgresql.yara

rule postgresql: medium {
  meta:
    description = "accesses PostgreSQL databases"
    confidence  = "0.66"

  strings:
$ref  = "postgresql" fullword
    $ref2 = "github.com/go-pg" fullword
  condition:
    any of them
}
