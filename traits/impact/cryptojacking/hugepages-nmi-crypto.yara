// Migrated from malcontent: impact/cryptojacking/hugepages_nmi_crypto.yara

rule hugepages_probably_miner: high {
  meta:
    description = "modifies memory configuration, likely miner"
    mbc         = "OB0010"
    attack      = "T1496"
    confidence  = "0.66"

  strings:
$hugepages  = "vm.nr_hugepages"
    $s_watchdog = "kernel.nmi_watchdog"
    $s_wallet   = "wallet"
    $s_xmr      = "xmr"
  condition:
    $hugepages and any of ($s*)
}
