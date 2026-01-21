// Migrated from malcontent: evasion/time/php_no_time_limit.yara

rule php_no_time_limit: medium {
  meta:
    description = "disables execution time limit"
    confidence  = "0.66"
    filetypes   = "php"

  strings:
$ref = "set_time_limit(0)"
  condition:
    $ref
}
