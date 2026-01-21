// Migrated from malcontent: fs/path/etc.yara

rule etc_path {
  meta:
    description = "path reference within /etc"
    capability  = "true"
    confidence  = "0.66"

  strings:
$resolv = /\/etc\/[a-z\.\-\/]{4,32}/
  condition:
    any of them
}
