// Migrated from malcontent: credential/cloud/gcloud.yara

rule gcloud_config_value: medium {
  meta:
    description = "Access gcloud configuration files"
    mbc         = "OB0004"
    attack      = "T1552"
    confidence  = "0.66"

  strings:
$ref  = ".config/gcloud"
    $ref2 = "application_default_credentials.json"
  condition:
    any of them
}
