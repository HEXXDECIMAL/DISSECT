// Migrated from malcontent: fs/path/dev-null.yara

rule dev_null: harmless {
  meta:
    description = "References /dev/null"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "/dev/null"
  condition:
    any of them
}
