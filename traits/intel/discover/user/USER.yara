// Migrated from malcontent: discover/user/USER.yara

rule USER {
  meta:
    description = "Looks up the USER name of the current user"
    mbc         = "E1033"
    attack      = "T1033"
    confidence  = "0.66"
    ref         = "https://man.openbsd.org/login.1#ENVIRONMENT"

  strings:
$ref     = "USER" fullword
    $envget  = "getenv"
    $env     = "ENV" fullword
    $environ = "environ" fullword
  condition:
    $ref and any of ($e*)
}
