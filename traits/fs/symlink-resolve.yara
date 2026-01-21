// Migrated from malcontent: fs/symlink-resolve.yara

rule realpath {
  meta:
    description = "resolves symbolic links"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "rpath"
    ref         = "https://man7.org/linux/man-pages/man3/realpath.3.html"

  strings:
$ref = "realpath" fullword
  condition:
    $ref
}
