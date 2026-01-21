// Migrated from malcontent: evasion/covert-location/wordpress-pre_term_name.yara

rule pre_term_name {
  meta:
    confidence  = "0.66"

  strings:
$ref = "<pre_term_name("
  condition:
    any of them
}
