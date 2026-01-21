// Migrated from malcontent: credential/cloud/dot_env.yara

rule dot_env_getter: high {
  meta:
    description = "Requests /.env URLs via HTTP"
    mbc         = "OB0004"
    attack      = "T1552"
    confidence  = "0.66"

  strings:
$ref = "GET /.env"
  condition:
    any of them
}
