// Migrated from malcontent: os/kernel/opencl.yara

rule OpenCL: medium {
  meta:
    description = "support for OpenCL"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "OpenCL" fullword
  condition:
    any of them
}
