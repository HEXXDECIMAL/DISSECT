// Migrated from malcontent: process/pthreads.yara

rule pthreads: harmless {
  meta:
    description = "Uses pthreads"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://en.wikipedia.org/wiki/Pthreads"

  strings:
$init = "pthread_cond_init" fullword
    $wait = "pthread_cond_wait" fullword
    $join = "pthread_join" fullword
  condition:
    any of them
}
