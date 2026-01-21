// Migrated from malcontent: process/terminate/terminate.yara

rule TerminateProcess: medium {
  meta:
    description = "terminate a process"
    mbc         = "C0039"
    confidence  = "0.66"

  strings:
$kill = "KillProcess" fullword
    $term = "TerminateProcess" fullword
  condition:
    any of them
}
