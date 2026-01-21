// Migrated from malcontent: fs/file/file-flags-change.yara

rule chflags {
  meta:
    description = "May update file flags using chflags"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://man.freebsd.org/cgi/man.cgi?chflags(1)"

  strings:
$chflags = "chflags" fullword
  condition:
    any of them
}
