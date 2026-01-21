// Migrated from malcontent: data/embedded/embedded-pem-certificate.yara

rule begin_cert {
  meta:
    description = "Contains embedded PEM certificate"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "-----BEGIN CERTIFICATE-----"
  condition:
    any of them
}
