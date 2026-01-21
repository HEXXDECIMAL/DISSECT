// Migrated from malcontent: collect/localstorage.yara

rule localstorage: medium {
  meta:
    description = "accesses browser local storage"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$ref = "localStorage.get"
  condition:
    any of them
}
