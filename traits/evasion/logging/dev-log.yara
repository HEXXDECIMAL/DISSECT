// Migrated from malcontent: evasion/logging/dev_log.yara

rule full: medium linux {
  meta:
    description = "device where local syslog messages are read"
    confidence  = "0.66"

  strings:
$val = "/dev/log" fullword
  condition:
    $val
}
