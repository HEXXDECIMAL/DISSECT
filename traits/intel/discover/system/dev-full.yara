// Migrated from malcontent: discover/system/dev_full.yara

rule dev_full: harmless linux {
  meta:
    description = "tests full disk behavior"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"

  strings:
$val = "/dev/full" fullword
  condition:
    $val
}
