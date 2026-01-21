// Migrated from malcontent: evasion/bypass_security/linux/selinux_disable.yara

rule selinux_disable_val: high {
  meta:
    description = "disables SELinux security control"
    confidence  = "0.66"

  strings:
$ref1 = "SELINUX=disabled"
    $ref2 = "setenforce 0"
  condition:
    any of them
}
