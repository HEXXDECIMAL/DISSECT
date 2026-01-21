// Migrated from malcontent: discover/permissions/capabilities.yara

rule process_capabilities_val: medium {
  meta:
    description = "enumerates Linux capabilities for process"
    confidence  = "0.66"

  strings:
$capsh       = "capsh" fullword
    $self_status = "/proc/self/status"
  condition:
    all of them
}
