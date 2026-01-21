// Migrated from malcontent: fs/proc/sys-kernel-osrelease.yara

rule proc_kernel_osrelease: medium linux {
  meta:
    description = "gets kernel release information"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "/proc/sys/kernel/osrelease" fullword
  condition:
    any of them
}
