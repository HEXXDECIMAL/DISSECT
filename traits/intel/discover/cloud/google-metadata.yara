// Migrated from malcontent: discover/cloud/google-metadata.yara

rule google_metadata {
  meta:
    description = "Includes the token required to use the Google Cloud Platform metadata server"
    mbc         = "E1580"
    attack      = "T1580"
    confidence  = "0.66"

  strings:
$ref = "Metadata-Flavor"
  condition:
    any of them
}
