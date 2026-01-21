// Migrated from malcontent: anti-static/obfuscation/python_setuptools.yara

import "math"


rule setuptools_builtins: medium {
  meta:
    description = "Python library installer that references builtins"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$ref = "__builtins__" fullword
  condition:
    any of them
}
