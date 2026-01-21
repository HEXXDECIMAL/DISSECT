// Migrated from malcontent: os/fd/sendfile.yara

rule sendfile {
  meta:
    description = "transfer data between file descriptors"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "sendfile"
    ref         = "https://man7.org/linux/man-pages/man2/sendfile.2.html"

  strings:
$ref  = "sendfile" fullword
    $ref2 = "syscall.Sendfile" fullword
  condition:
    any of them
}
