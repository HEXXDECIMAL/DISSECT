// Migrated from malcontent: discover/network/netstat.yara

rule netstat: medium {
  meta:
    description = "Uses 'netstat' for network information"
    mbc         = "E1016"
    attack      = "T1016"
    confidence  = "0.66"

  strings:
$ref1 = /netstat[ \-a-z\|]{0,16}/
  condition:
    all of them
}
