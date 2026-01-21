// Migrated from malcontent: fs/path/var-containers.yara

rule var_containers_path: high macos {
  meta:
    description = "path reference within /var/containers"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = /\/var\/containers\/[\%\w\.\-\/]{4,32}/ fullword
  condition:
    $ref
}
