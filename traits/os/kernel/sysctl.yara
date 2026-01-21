// Migrated from malcontent: os/kernel/sysctl.yara

rule sysctl: harmless {
  meta:
    description = "get or set kernel stat"
    capability  = "true"
    confidence  = "0.66"

  strings:
$sysctl = "sysctl"
    $Sysctl = "Sysctl"
  condition:
    any of them
}
