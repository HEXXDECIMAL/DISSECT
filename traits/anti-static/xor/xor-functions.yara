// Migrated from malcontent: anti-static/xor/xor-functions.yara

rule xor_eval: medium {
  meta:
    description = "eval( xor'd"
    confidence  = "0.66"

  strings:
$b_eval  = "eval(" xor(1-31)
    $b_eval2 = "eval(" xor(33-255)
  condition:
    any of ($b_*)
}
