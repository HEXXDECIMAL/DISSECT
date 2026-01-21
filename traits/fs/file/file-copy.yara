// Migrated from malcontent: fs/file/file-copy.yara

rule file_copy: medium {
  meta:
    description = "copy files"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = /copyFile/ fullword
  condition:
    any of them
}

rule file_copy_cp: medium {
  meta:
    description = "copy files using cp"
    confidence  = "0.66"

  strings:
$ref = /cp [-\w ]{0,2}[ \$\w\/\.\-]{0,32}/ fullword
  condition:
    any of them
}

rule file_copy_force: medium {
  meta:
    description = "forcibly copy files using cp -f"
    confidence  = "0.66"

  strings:
$ref = /cp [-\w ]{0,2}f [ \$\w\/\.\-]{0,32}/ fullword
  condition:
    any of them
}
