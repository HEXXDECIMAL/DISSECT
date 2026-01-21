// Migrated from malcontent: fs/file/file-open-by_handle.yara

rule by_handle {
  meta:
    description = "obtain handle for a pathname and open file via a handle"
    confidence  = "0.66"
    syscall     = "open_by_handle_at"
    capability  = "CAP_DAC_READ_SEARCH"
    ref         = "https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html"

  strings:
$ref  = "name_to_handle_at" fullword
    $ref2 = "open_by_handle_at" fullword
  condition:
    any of them
}
