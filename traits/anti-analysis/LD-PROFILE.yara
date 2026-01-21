// Migrated from malcontent: anti-behavior/LD_PROFILE.yara

rule env_LD_PROFILE: medium {
  meta:
    description = "may check if dynamic linker profiling is enabled"
    confidence  = "0.66"
    filetypes   = "elf,macho"

  strings:
$val = "LD_PROFILE" fullword
  condition:
    all of them
}
