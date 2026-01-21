// Migrated from malcontent: privesc/generic.yara

rule runWithPrivileges: high {
  meta:
    description = "runs with privileges"
    confidence  = "0.66"

  strings:
$ref = "runWithPrivileges"
  condition:
    any of them
}
