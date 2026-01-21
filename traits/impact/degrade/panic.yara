// Migrated from malcontent: impact/degrade/panic.yara

rule raise_hard_error: medium windows {
  meta:
    description = "crashes (bluescreens) the machine"
    mbc         = "OB0010"
    attack      = "T1499"
    confidence  = "0.66"
    filetypes   = "exe,pe,py"

  strings:
$crash = "NtRaiseHardError" fullword
  condition:
    filesize < 1MB and any of them
}
