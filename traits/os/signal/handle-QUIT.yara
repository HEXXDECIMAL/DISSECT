// Migrated from malcontent: os/signal/handle-QUIT.yara

rule sigaction_SIGQUIT: harmless {
  meta:
    description = "Listen for SIGQUIT (kill) events"
    capability  = "true"
    confidence  = "0.66"

  strings:
$sigaction = "sigaction" fullword
    $sigalrm   = "QUIT"
  condition:
    all of them
}
