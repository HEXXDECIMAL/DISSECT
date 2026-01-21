// Migrated from malcontent: os/kernel/dispatch-semaphore.yara

rule dispatch_sem {
  meta:
    description = "Uses Dispatch Semaphores"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://developer.apple.com/documentation/dispatch/dispatch_semaphore"

  strings:
$ref = "dispatch_semaphore_signal"
  condition:
    any of them
}
