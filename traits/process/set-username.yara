// Migrated from malcontent: process/username-set.yara

rule setlogin: medium {
  meta:
    description = "set login name"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "setlogin"
    pledge      = "id"

  strings:
$ref = "setlogin" fullword
  condition:
    any of them
}
