// Migrated from malcontent: fs/proc/self-cgroup.yara

rule pid_self_cgroup: medium {
  meta:
    description = "accesses /proc files within own cgroup"
    capability  = "true"
    confidence  = "0.66"

  strings:
$val = /\/proc\/self\/cgroup[a-z\/\-]{0,32}/
  condition:
    any of them
}
