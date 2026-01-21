// Migrated from malcontent: impact/degrade/bluescreen.yara

rule python_bluesscreen: high windows {
  meta:
    description = "causes a blue screne (crash)"
    mbc         = "OB0010"
    attack      = "T1499"
    confidence  = "0.66"

  strings:
$bluescreen = "RtlAdjustPrivilege(19, 1,"
  condition:
    filesize < 256KB and any of them
}
