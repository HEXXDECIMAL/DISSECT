// Migrated from malcontent: discover/components/docker.yara

rule docker_ps: medium {
  meta:
    description = "enumerates Docker containers"
    confidence  = "0.66"

  strings:
$ref = "docker ps" fullword
  condition:
    any of them
}

rule docker_version: medium {
  meta:
    description = "gets docker version information"
    confidence  = "0.66"

  strings:
$ref = "docker version" fullword
  condition:
    any of them
}
