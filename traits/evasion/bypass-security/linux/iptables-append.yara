// Migrated from malcontent: evasion/bypass_security/linux/iptables_append.yara

rule iptables_append: medium linux {
  meta:
    description = "Appends rules to a iptables chain"
    confidence  = "0.66"
    syscall     = "posix_spawn"
    pledge      = "exec"

  strings:
$ref = /iptables [\-\w% ]{0,8} -A[\-\w% ]{0,32}/
  condition:
    any of them
}

rule iptables_append_broken: medium linux {
  meta:
    description = "Appends rules to a iptables chain"
    confidence  = "0.66"

  strings:
$iptables = "iptables" fullword
    $A        = "-A"
    $INPUT    = "INPUT"
  condition:
    filesize < 5MB and all of them
}
