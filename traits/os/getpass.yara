// Migrated from malcontent: exec/tty/getpass.yara

rule getpass {
  meta:
    description = "prompt for a password within a terminal"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "getpass" fullword
  condition:
    any of them
}
