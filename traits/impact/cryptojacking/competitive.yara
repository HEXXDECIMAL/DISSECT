// Migrated from malcontent: impact/cryptojacking/competitive.yara

rule killer_miner_panchansminingisland: critical {
  meta:
    description = "crypto miner virus"
    mbc         = "OB0010"
    attack      = "T1496"
    confidence  = "0.66"
    filetypes   = "elf"

  strings:
$ = "killer"
    $ = "miner"
    $ = "p2p"
    $ = "protector"
    $ = "rootkit"
    $ = "spreader"
    $ = "updater"

    $not_pypi_index = "testpack-id-lb001"
  condition:
    filesize < 120MB and 6 of them and none of ($not*)
}
