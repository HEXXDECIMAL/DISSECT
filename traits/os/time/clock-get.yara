// Migrated from malcontent: os/time/clock-get.yara

rule bsd_time: harmless {
  meta:
    confidence  = "0.66"

  strings:
$_time = "_time" fullword
  condition:
    any of them
}

rule gettimeofday: harmless {
  meta:
    description = "get time"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "gettimeofday"
    ref         = "https://man7.org/linux/man-pages/man2/gettimeofday.2.html"

  strings:
$ref = "gettimeofday" fullword
  condition:
    any of them
}
