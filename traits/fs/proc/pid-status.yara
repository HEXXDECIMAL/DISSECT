// Migrated from malcontent: fs/proc/pid-status.yara

import "math"


rule proc_status: medium {
  meta:
    description = "access status fields for other processes"
    capability  = "true"
    confidence  = "0.66"

  strings:
$string = "/proc/%s/status" fullword
    $digit  = "/proc/%d/status" fullword
    $python = "/proc/{}/status" fullword
  condition:
    any of them
}

rule proc_status_near: medium {
  meta:
    description = "access status fields for other processes"
    confidence  = "0.66"

  strings:
$proc = "/proc" fullword
    $fmt  = /%[sd]\/status/ fullword
  condition:
    all of them and math.abs(@proc - @fmt) < 128
}
