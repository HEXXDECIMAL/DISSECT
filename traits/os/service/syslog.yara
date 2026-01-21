// Migrated from malcontent: os/service/syslog.yara

rule syslog: harmless {
  meta:
    description = "Use the syslog (system log) service"
    confidence  = "0.66"
    capability  = "CAP_SYSLOG"

  strings:
$ref = "syslog" fullword
  condition:
    all of them
}
