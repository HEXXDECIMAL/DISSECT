// Migrated from malcontent: evasion/self_deletion/remove_self.yara

rule self_delete: high {
  meta:
    description = "may delete itself to avoid detection"
    confidence  = "0.66"

  strings:
$self    = "RemoveSelfExecutable"
    $syscall = "syscall.Unlink"
  condition:
    filesize < 20MB and all of them
}
