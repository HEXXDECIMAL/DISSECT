// Migrated from malcontent: fs/proc/arbitrary-pid.yara

rule proc_arbitrary: medium {
  meta:
    description = "access /proc for arbitrary pids"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = /\/proc\/[%{$][\/\$\w\}]{0,12}/
  condition:
    $ref
}

rule pid_match: medium {
  meta:
    description = "scan /proc for matching pids"
    confidence  = "0.66"

  strings:
$string_val = /\/proc\/\\d[\/\$\w\}]{0,12}/
  condition:
    any of them
}
