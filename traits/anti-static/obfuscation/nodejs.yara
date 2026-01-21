// Migrated from malcontent: anti-static/obfuscation/nodejs.yara

rule nodejs_buffer_from: medium {
  meta:
    description = "loads arbitrary bytes from a buffer"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$ref = /Buffer\.from\(\[[\d,]{8,63}\)/
  condition:
    any of them
}

rule nodejs_buffer_from_many: high {
  meta:
    description = "loads many arbitrary bytes from a buffer"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$ref = /Buffer\.from\(\[[\d,]{63,2048}/
  condition:
    any of them
}
