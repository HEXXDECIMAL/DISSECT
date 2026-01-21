// Migrated from malcontent: anti-static/obfuscation/bool.yara

rule js_while_true_obfuscation: medium {
  meta:
    description = "obfuscated 'while true' loop"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$ref  = "while (!![])"
    $ref2 = "while(!![])"
  condition:
    any of them
}
