// Migrated from malcontent: impact/wipe/shadow_copy.yara

rule high_deletion: high windows {
  meta:
    description = "high Shadow Copy deletion - possible ransomware"
    mbc         = "OB0010"
    attack      = "T1485"
    confidence  = "0.66"

  strings:
// extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $vss_admin = "vssadmin delete shadows" ascii nocase
    $vss_exec  = ".exe delete shadows" ascii nocase
    $wmic      = " shadowcopy delete" ascii wide nocase
    $wbadmin   = " delete catalog -quiet" ascii wide nocase
  condition:
    any of them
}
