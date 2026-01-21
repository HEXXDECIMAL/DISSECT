// Migrated from malcontent: discover/system/dmesg.yara

rule dmesg {
  meta:
    description = "accesses the kernel log ring buffer"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"

  strings:
$dmesg = "dmesg" fullword
  condition:
    any of them
}
