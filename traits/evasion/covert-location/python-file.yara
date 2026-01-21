// Migrated from malcontent: evasion/covert-location/python_file.yara

rule python_reads_itself: high {
  meta:
    description = "python file reads itself, possibly hiding additional instructions"
    confidence  = "0.66"
    filetype    = "py"

  strings:
$ref = "open(__file__," fullword
  condition:
    filesize < 1MB and any of them
}
