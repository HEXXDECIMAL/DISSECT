// Migrated from malcontent: persist/plugin.yara

rule plugin_persist: high {
  meta:
    description = "may use persistence plugins"
    confidence  = "0.66"

  strings:
$ref = "plugin_persist"
  condition:
    any of them
}
