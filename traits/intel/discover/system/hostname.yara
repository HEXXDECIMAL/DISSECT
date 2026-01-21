// Migrated from malcontent: discover/system/hostname.yara

rule gethostname {
  meta:
    description = "get computer host name"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    pledge      = "sysctl"
    syscall     = "sysctl"
    ref         = "https://man7.org/linux/man-pages/man2/sethostname.2.html"

  strings:
$gethostname = "gethostname"
    $proc        = "/proc/sys/kernel/hostname"
    $python      = "socket.gethostname"
    $nodejs      = "os.hostname()"
    $js          = "os.default.hostname"
  condition:
    any of them
}
