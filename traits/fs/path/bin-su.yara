// Migrated from malcontent: fs/path/bin-su.yara

rule bin_su {
  meta:
    description = "Calls /bin/su"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "/bin/su"
  condition:
    any of them
}
