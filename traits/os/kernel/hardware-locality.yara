// Migrated from malcontent: os/kernel/hardware-locality.yara

rule hwloc {
  meta:
    description = "Uses hardware locality (NUMA, etc)"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://linux.die.net/man/7/hwloc"

  strings:
$ref = "hwloc" fullword
  condition:
    any of them
}
