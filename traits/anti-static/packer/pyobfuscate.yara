// Migrated from malcontent: anti-static/packer/pyobfuscate.yara

rule pyobfuscate: high {
  meta:
    description = "uses 'pyobfuscate' packer"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$def         = "def" fullword
    $pyobfuscate = "pyobfuscate" fullword
  condition:
    filesize < 1MB and all of them
}
