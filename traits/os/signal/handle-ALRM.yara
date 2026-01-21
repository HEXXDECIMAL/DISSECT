// Migrated from malcontent: os/signal/handle-ALRM.yara

rule sigaction_ALRM: harmless {
  meta:
    description = "Listen for SIGALRM (timeout) events"
    capability  = "true"
    confidence  = "0.66"

  strings:
$sigaction = "sigaction" fullword
    $sigalrm   = "ALRM"
  condition:
    all of them
}
