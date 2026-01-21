// Migrated from malcontent: process/terminate/arbitrary.yara

rule kill_d: high {
  meta:
    description = "kills arbitrary process, hiding errors"
    mbc         = "C0039"
    confidence  = "0.66"

  strings:
$kill_9 = "kill %d 2>/dev/null"
  condition:
    any of them
}

rule kill_9_d: high {
  meta:
    description = "terminates arbitrary process, hiding errors"
    mbc         = "C0039"
    confidence  = "0.66"

  strings:
$kill_9 = "kill -9 %d 2>/dev/null"
  condition:
    any of them
}
