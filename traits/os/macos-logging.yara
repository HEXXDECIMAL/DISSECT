// Migrated from malcontent: os/macos_logging.yara

rule os_log: harmless {
  meta:
    description = "Use the macOS system log service"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "os_log" fullword
  condition:
    all of them
}
