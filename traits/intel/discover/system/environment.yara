// Migrated from malcontent: discover/system/environment.yara

rule os_environ: medium {
  meta:
    description = "Dump values from the environment"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$ref = "os.environ.items()" fullword
  condition:
    any of them
}
