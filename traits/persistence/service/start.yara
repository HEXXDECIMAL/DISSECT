// Migrated from malcontent: persist/service/start.yara

rule service_start {
  meta:
    mbc         = "E1543"
    attack      = "T1543"
    confidence  = "0.66"

  strings:
$ref           = /service [\w\_\- ]{1,16} start/
    $not_osquery   = "OSQUERY"
    $not_not_start = "service not start"
    $not_must      = "service name must start"
  condition:
    $ref and none of ($not*)
}
