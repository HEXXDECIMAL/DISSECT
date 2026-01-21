// Migrated from malcontent: anti-static/packer/cx_freeze.yara

rule cxFreeze_Python_executable: high {
  meta:
    description = "uses cxFreeze packer"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$cxfreeze      = "cx_Freeze"
    $not_importlib = "tool like cx_Freeze"
  condition:
    filesize < 10485760 and $cxfreeze and none of ($not*)
}
