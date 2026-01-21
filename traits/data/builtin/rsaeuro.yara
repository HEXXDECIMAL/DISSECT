// Migrated from malcontent: data/builtin/rsaeuro.yara

rule rsaeuro_user: medium {
  meta:
    description = "includes the RSAEURO toolkit"
    capability  = "true"
    confidence  = "0.66"

  strings:
$toolkit = "RSAEURO Toolkit"
  condition:
    any of them
}
