// Migrated from malcontent: fs/proc/pid-statistics.yara

rule proc_pid_stat_val {
  meta:
    description = "access process stats using /pid/%d/stat"
    capability  = "true"
    confidence  = "0.66"

  strings:
$string = "/proc/%s/stat" fullword
    $digit  = "/proc/%d/stat" fullword
  condition:
    any of them
}
