// Migrated from malcontent: anti-behavior/LD_DEBUG.yara

rule env_LD_DEBUG: medium {
  meta:
    description = "may check if dynamic linker debugging is enabled"
    confidence  = "0.66"
    filetypes   = "elf,macho"

  strings:
$val = "LD_DEBUG" fullword
  condition:
    all of them
}
