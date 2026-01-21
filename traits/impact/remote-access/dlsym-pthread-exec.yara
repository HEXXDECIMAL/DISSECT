// Migrated from malcontent: impact/remote_access/dlsym_pthread_exec.yara

rule dlsym_pthread_exec: high {
  meta:
    description = "Resolves library, creates threads, calls programs"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$dlsym   = "dlsym" fullword
    $openpty = "pthread_create" fullword
    $system  = "execl" fullword
  condition:
    all of them in (1000..3000)
}
