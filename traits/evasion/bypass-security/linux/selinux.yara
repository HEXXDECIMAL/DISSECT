// Migrated from malcontent: evasion/bypass_security/linux/selinux.yara

rule selinux: medium {
  meta:
    description = "alters the SELinux enforcement level"
    confidence  = "0.66"

  strings:
$ref1 = "SELINUX"
    $ref2 = "setenforce"
  condition:
    all of them
}
