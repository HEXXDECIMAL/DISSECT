// Migrated from malcontent: os/time/clock-set.yara

rule bsd_adjtime {
  meta:
    description = "set time via system clock"
    confidence  = "0.66"
    syscall     = "adjtime"
    pledge      = "settime"
    capability  = "CAP_SYS_TIME"

  strings:
$adjtime = "adjtime" fullword
  condition:
    any of them
}

rule bsd_settimeofday {
  meta:
    description = "set time via system clock"
    confidence  = "0.66"
    syscall     = "settimeofday"
    capability  = "CAP_SYS_TIME"
    pledge      = "settime"

  strings:
$settimeofday = "settimeofday" fullword
  condition:
    any of them
}

rule linux_adjtimex {
  meta:
    description = "set time via system clock"
    confidence  = "0.66"
    syscall     = "adjtimex"
    capability  = "CAP_SYS_TIME"
    pledge      = "settime"

  strings:
$adjtimex = "adjtimex" fullword
  condition:
    any of them
}

rule linux_adjfreq {
  meta:
    description = "set time via system clock"
    confidence  = "0.66"
    syscall     = "adjfreq"
    pledge      = "settime"
    capability  = "CAP_SYS_TIME"

  strings:
$adjfreq = "adjfreq" fullword
  condition:
    any of them
}

rule linux_clock_settime {
  meta:
    description = "set time via system clock"
    confidence  = "0.66"
    syscall     = "clock_settime"
    pledge      = "settime"
    capability  = "CAP_SYS_TIME"

  strings:
$ref = "clock_settime" fullword
  condition:
    any of them
}
