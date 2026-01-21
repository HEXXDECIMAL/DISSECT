// Migrated from malcontent: hw/cpu.yara

rule sys_devices_cpu: linux medium {
  meta:
    description = "Get information about CPUs"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "/sys/devices/system/cpu" fullword
  condition:
    any of them
}

rule CpuInfoAndModel: macos medium {
  meta:
    description = "Get information about CPUs"
    confidence  = "0.66"

  strings:
$ref = "CpuInfoAndModel"
  condition:
    any of them
}
