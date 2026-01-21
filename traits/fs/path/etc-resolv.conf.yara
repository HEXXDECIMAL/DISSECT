// Migrated from malcontent: fs/path/etc-resolv.conf.yara

rule etc_resolv_conf {
  meta:
    description = "accesses DNS resolver configuration"
    capability  = "true"
    confidence  = "0.66"

  strings:
$resolv = "/etc/resolv.conf"
  condition:
    any of them
}
