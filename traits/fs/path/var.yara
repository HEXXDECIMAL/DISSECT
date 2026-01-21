// Migrated from malcontent: fs/path/var.yara

rule var_path {
  meta:
    description = "path reference within /var"
    capability  = "true"
    confidence  = "0.66"

  strings:
$resolv = /\/var\/[%\w\.\-\/]{0,64}/
  condition:
    any of them
}
