// Migrated from malcontent: credential/ssh/putty.yara

rule putty_ssh_sessions_reference {
  meta:
    confidence  = "0.66"

  strings:
$putty = "Software\\SimonTatham\\PuTTY\\Sessions"
  condition:
    any of them
}
