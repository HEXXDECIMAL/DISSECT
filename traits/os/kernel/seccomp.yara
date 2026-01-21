// Migrated from malcontent: os/kernel/seccomp.yara

rule seccomp {
  meta:
    description = "operate on Secure Computing state of the process"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "seccomp"
    ref         = "https://man7.org/linux/man-pages/man2/seccomp.2.html"

  strings:
$uname = "seccomp" fullword
  condition:
    any of them
}
