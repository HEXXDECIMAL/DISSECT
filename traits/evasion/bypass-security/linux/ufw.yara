// Migrated from malcontent: evasion/bypass_security/linux/ufw.yara

rule ufw: medium {
  meta:
    description = "interacts with the ufw firewall"
    confidence  = "0.66"

  strings:
$ref = "ufw" fullword

    $arg_disable = "disable" fullword
    $arg_allow   = "allow" fullword
    $arg_deny    = "deny" fullword
    $arg_enable  = "enable" fullword
  condition:
    $ref and any of ($arg*)
}
