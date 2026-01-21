// Migrated from malcontent: fs/path/etc-hosts.yara

rule etc_hosts: medium {
  meta:
    description = "references /etc/hosts"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "/etc/hosts"
  condition:
    any of them
}
