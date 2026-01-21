// Migrated from malcontent: fs/watch.yara

rule inotify {
  meta:
    description = "monitors filesystem events"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "inotify" fullword
    $ref2 = "fswatch" fullword
    $ref3 = "fswatcher" fullword
  condition:
    any of them
}
