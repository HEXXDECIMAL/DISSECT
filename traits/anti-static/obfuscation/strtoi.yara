// Migrated from malcontent: anti-static/obfuscation/strtoi.yara

rule sketchy_parseint_math: medium {
  meta:
    description = "complex math and string to integer conversion"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$m1         = /\d{2,16}[\-\+\*\^]\w{1,8}/
    $m2         = /\w{1,8}[\-\+\*\^]\d{2,16}/
    $f_parseInt = "parseInt"
  condition:
    filesize < 1MB and any of ($f*) and ((#m1 > 5) or (#m2 > 5))
}
