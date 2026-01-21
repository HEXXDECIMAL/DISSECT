// Migrated from malcontent: os/sync/semaphore-user.yara

rule semaphore_user {
  meta:
    description = "uses semaphores to synchronize data between processes or threads"
    capability  = "true"
    confidence  = "0.66"

  strings:
$semaphore_create = "semaphore_create" fullword
    $semaphore_wait   = "semaphore_wait" fullword
    $semaphore_signal = "semaphore_signal" fullword
  condition:
    any of them
}
