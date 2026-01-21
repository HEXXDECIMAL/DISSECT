// Migrated from malcontent: anti-static/packer/py_vare.yara

rule Vare_Obfuscator: critical {
  meta:
    description = "obfuscated with https://github.com/saintdaddy/Vare-Obfuscator"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$var  = "__VareObfuscator__"
    $var2 = "Vare Obfuscator"
  condition:
    any of them
}
