// Migrated from malcontent: fs/file/file-permissions-setuid.yara

rule make_setuid {
  meta:
    confidence  = "0.66"
    ref         = "https://en.wikipedia.org/wiki/Setuid"

  strings:
$chmod_47  = "chmod 47"
    $chmod_s   = "chmod +s"
    $setsuid   = "setSuid"
    $set_seuid = "set_suid"
  condition:
    any of them
}
