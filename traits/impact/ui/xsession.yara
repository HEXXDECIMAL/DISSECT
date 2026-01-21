// Migrated from malcontent: impact/ui/xsession.yara

rule xsession: medium {
  meta:
    description = "makes references to Xsession"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$cookie = "Xsession"
  condition:
    any of them
}
