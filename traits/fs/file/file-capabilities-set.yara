// Migrated from malcontent: fs/file/file-capabilities-set.yara

rule setfcap {
  meta:
    description = "Set file capabilities"
    confidence  = "0.66"
    pledge      = "wpath"
    ref         = "https://man7.org/linux/man-pages/man7/capabilities.7.html"
    capability  = "CAP_SETFCAP"

  strings:
$ref1 = "scap_set_nsowner" fullword
    $ref2 = "setcap" fullword
    $ref3 = "cap_set_file" fullword
    $ref4 = "cap_set_fd" fullword
  condition:
    any of them
}
