// Migrated from malcontent: os/signal/handle.yara

rule libc: harmless {
  meta:
    confidence  = "0.66"

  strings:
$signal      = "_signal" fullword
    $sigaction   = "sigaction" fullword
    $sigismember = "sigismember" fullword
  condition:
    any of them
}

rule win_cntrl: low windows {
  meta:
    description = "Adds or removes handler function for the calling process"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "SetConsoleCtrlHandler"
  condition:
    any of them
}
