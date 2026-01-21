// Migrated from malcontent: discover/process/name.yara

rule progname: low {
  meta:
    description = "get the current process name"
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"
    ref         = "https://linux.die.net/man/3/program_invocation_short_name"

  strings:
$ref = "program_invocation_short_name"
  condition:
    any of them in (1000..3000)
}

rule process_name: medium {
  meta:
    description = "get the current process name"
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"

  strings:
$ref  = "processName"
    $ref2 = "process_name"
  condition:
    any of them
}
