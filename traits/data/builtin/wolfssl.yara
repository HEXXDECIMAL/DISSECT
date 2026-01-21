// Migrated from malcontent: data/builtin/wolfssl.yara

rule wolfssl: medium {
  meta:
    description = "This binary includes WolfSSL"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "WolfSSL"
    $ref2 = "WOLFSSL_"
  condition:
    any of them
}
