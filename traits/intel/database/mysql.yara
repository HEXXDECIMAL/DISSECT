// Migrated from malcontent: collect/databases/mysql.yara

rule mysql: medium {
  meta:
    description = "accesses MySQL databases"
    confidence  = "0.66"

  strings:
$ref = "mysql" fullword
  condition:
    $ref
}
