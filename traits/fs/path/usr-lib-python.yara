// Migrated from malcontent: fs/path/usr-lib-python.yara

rule usr_lib_python_path_val: medium {
  meta:
    description = "References paths within /usr/lib/python"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = /\/usr\/lib\/python[\w\-\.\/]{0,128}/
  condition:
    $ref
}
