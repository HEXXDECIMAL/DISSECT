// Migrated from malcontent: data/embedded/embedded-pem-test_key.yara

rule testing_key {
  meta:
    description = "Contains TESTING KEY directive"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "TESTING KEY-----"
  condition:
    any of them
}
