// Migrated from malcontent: evasion/logging/install.yara

rule var_log_install: high {
  meta:
    description = "accesses software installation logs"
    confidence  = "0.66"

  strings:
$ref = "/var/log/install.log" fullword
  condition:
    $ref
}
