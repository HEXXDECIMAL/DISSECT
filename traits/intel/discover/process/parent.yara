// Migrated from malcontent: discover/process/parent.yara

rule getppid {
  meta:
    description = "gets parent process ID"
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"

  strings:
$ref  = "getppid" fullword
    $ref2 = "process.ppid" fullword
  condition:
    any of them
}
