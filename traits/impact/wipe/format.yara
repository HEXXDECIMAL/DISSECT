// Migrated from malcontent: impact/wipe/format.yara

rule format_c: critical windows {
  meta:
    description = "forcibly formats the C:\\ drive"
    mbc         = "OB0010"
    attack      = "T1485"
    confidence  = "0.66"

  strings:
$format = /(format|FORMAT).{1,4}[Cc]:\\.{1,4}\/[yY]/
  condition:
    any of them
}
