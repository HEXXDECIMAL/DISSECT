// Migrated from malcontent: evasion/bypass_security/linux/iptables_delete.yara

rule iptables_chain_delete: medium {
  meta:
    description = "Deletes rules from a iptables chain"
    confidence  = "0.66"
    syscall     = "posix_spawn"
    pledge      = "exec"

  strings:
$ref = /iptables [\-\w% ]{0,8} -D[\-\w% ]{0,32}/
  condition:
    any of them
}
