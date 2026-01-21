// Migrated from malcontent: os/signal/handle-INFO.yara

rule sigaction_SIGINFO: harmless {
  meta:
    description = "Listen for SIGINFO (information) events"
    capability  = "true"
    confidence  = "0.66"

  strings:
$sigaction = "sigaction" fullword
    $sigalrm   = "SIGINFO"
  condition:
    all of them
}
