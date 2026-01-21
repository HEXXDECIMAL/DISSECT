// Migrated from malcontent: credential/os/gshadow.yara

rule etc_gshadow: medium {
  meta:
    description = "accesses /etc/gshadow (group passwords)"
    mbc         = "OB0004"
    attack      = "T1003"
    confidence  = "0.66"

  strings:
$ref = "etc/gshadow"
  condition:
    any of them
}
