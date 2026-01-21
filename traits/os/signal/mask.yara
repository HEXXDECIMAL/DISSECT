// Migrated from malcontent: os/signal/mask.yara

rule sigprocmask: harmless {
  meta:
    confidence  = "0.66"

  strings:
$sigprocmask = "sigprocmask"
  condition:
    any of them
}
