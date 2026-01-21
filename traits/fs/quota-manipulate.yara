// Migrated from malcontent: fs/quota-manipulate.yara

rule quotactl {
  meta:
    description = "manipulate disk quota"
    confidence  = "0.66"
    capability  = "CAP_SYS_SYSADMIN"
    syscall     = "quotactl"

  strings:
$ref = "quotactl" fullword
  condition:
    any of them
}
