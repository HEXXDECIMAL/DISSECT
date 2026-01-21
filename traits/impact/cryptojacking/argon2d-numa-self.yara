// Migrated from malcontent: impact/cryptojacking/argon2d_numa_self.yara

rule probably_a_miner: high {
  meta:
    description = "probably a cryptocurrency miner"
    mbc         = "OB0010"
    attack      = "T1496"
    confidence  = "0.66"

  strings:
$argon     = "argon2d"
    $proc_self = "/proc/self"
    $numa      = "NUMA"
  condition:
    filesize < 10MB and all of them
}
