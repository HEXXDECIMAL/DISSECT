// Migrated from malcontent: evasion/mimicry/fake-library.yara

rule libnetresolv_fake_val: high {
  meta:
    description = "references fake library - possible dynamic library hijacking"
    confidence  = "0.66"
    ref         = "https://cert.gov.ua/article/6123309"

  strings:
$libnetresolv = "libnetresolv.so"
  condition:
    any of them
}

rule libs_fake_val: high {
  meta:
    description = "references fake library, possible dynamic library hijacking"
    confidence  = "0.66"
    ref         = "https://cert.gov.ua/article/6123309"

  strings:
$libnetresolv = "libs.so" fullword
  condition:
    any of them
}

rule libc_fake_number_val: high {
  meta:
    description = "references a non-standard libc library (normally libc.so.6)"
    confidence  = "0.66"
    ref         = "https://cert.gov.ua/article/6123309"

  strings:
$ref            = /libc.so.[234589]/
    $not_go_example = "libc.so.96.1"
  condition:
    $ref and none of ($not*)
}
