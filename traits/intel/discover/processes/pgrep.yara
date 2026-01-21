// Migrated from malcontent: discover/processes/pgrep.yara

rule pgrep: medium {
  meta:
    description = "Finds program in process table"
    confidence  = "0.66"

  strings:
$val = /pgrep[ \w\$]{0,32}/ fullword
  condition:
    $val
}
