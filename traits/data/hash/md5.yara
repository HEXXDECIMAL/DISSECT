// Migrated from malcontent: data/hash/md5.yara

rule MD5 {
  meta:
    description = "Uses the MD5 signature format"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = /MD5_[\w\:]{0,16}/
    $ref2 = /md5:[\w\:]{0,16}/
  condition:
    any of them
}

rule md5_verify: medium {
  meta:
    description = "Verifies MD5 signatures"
    confidence  = "0.66"

  strings:
$ref  = "md5 expect"
    $ref2 = "md5 mismatch"
    $ref3 = "FileMd5"
    $ref4 = "FileMD5"
  condition:
    any of them
}
