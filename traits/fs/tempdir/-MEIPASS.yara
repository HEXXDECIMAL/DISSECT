// Migrated from malcontent: fs/tempdir/_MEIPASS.yara

rule sys_MEIPASS: low {
  meta:
    description = "references PyInstaller bundle folder"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "sys._MEIPASS"
  condition:
    any of them
}
