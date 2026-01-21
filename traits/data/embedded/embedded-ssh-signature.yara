// Migrated from malcontent: data/embedded/embedded-ssh-signature.yara

rule ssh_signature: medium {
  meta:
    description = "Contains embedded SSH signature"
    capability  = "true"
    confidence  = "0.66"

  strings:
$sig = "--BEGIN SSH SIGNATURE--"
  condition:
    any of them
}
