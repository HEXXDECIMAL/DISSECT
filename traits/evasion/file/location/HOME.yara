// Migrated from malcontent: evasion/file/location/HOME.yara

rule custom_home: medium linux {
  meta:
    description = "overrides the HOME directory environment variable"
    confidence  = "0.66"

  strings:
$ref      = /HOME=\/[a-z][\.\w\/]{0,24}/ fullword
    $not_root = "HOME=/root"
  condition:
    $ref and none of ($not*)
}
