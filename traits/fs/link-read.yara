// Migrated from malcontent: fs/link-read.yara

rule readlink {
  meta:
    description = "read value of a symbolic link"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "readlink"
    pledge      = "rpath"
    ref         = "https://man7.org/linux/man-pages/man2/readlink.2.html"

  strings:
$ref  = "readlink" fullword
    $ref2 = "readlinkat" fullword
  condition:
    any of them
}
