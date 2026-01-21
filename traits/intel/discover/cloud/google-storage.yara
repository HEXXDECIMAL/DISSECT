// Migrated from malcontent: discover/cloud/google-storage.yara

rule go_import {
  meta:
    description = "Capable of using Google Cloud Storage (GCS)"
    mbc         = "E1580"
    attack      = "T1580"
    confidence  = "0.66"

  strings:
$ref = "cloud.google.com/go/storage" fullword
  condition:
    any of them
}
