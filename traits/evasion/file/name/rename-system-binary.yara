// Migrated from malcontent: evasion/file/name/rename_system_binary.yara

rule rename_system_binary: high {
  meta:
    description = "Renames system binary"
    confidence  = "0.66"

  strings:
$ref = /(mv|cp|ln) \/(bin|usr\/bin)\/[ \.\w\/]{0,64}/
  condition:
    $ref
}
