// Migrated from malcontent: impact/registry.yara

rule registry: medium {
  meta:
    description = "writes to the Windows registry"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$ref  = "winreg"
    $ref2 = "SetValueEx"
  condition:
    all of them
}
