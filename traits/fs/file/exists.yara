// Migrated from malcontent: fs/file/exists.yara

rule path_exists: low {
  meta:
    description = "check if a file exists"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "path.exists" fullword
  condition:
    any of them
}

rule java_exists: low {
  meta:
    description = "check if a file exists"
    confidence  = "0.66"
    filetypes   = "java"

  strings:
$ref  = "java/io/File" fullword
    $ref2 = "exists" fullword
  condition:
    all of them
}
