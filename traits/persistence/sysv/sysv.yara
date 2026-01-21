// Migrated from malcontent: persist/sysv/sysv.yara

rule sysv_persist: high {
  meta:
    description = "installs arbitrary files into SYSV-style init directories"
    confidence  = "0.66"

  strings:
$rc_d   = "/etc/rc%d.d/S%d%s"
    $init_d = "/etc/init.d/%s"
  condition:
    filesize < 5MB and any of them
}
