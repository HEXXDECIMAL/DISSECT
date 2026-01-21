// Migrated from malcontent: anti-static/obfuscation/padding.yara

rule msxml2_http: critical {
  meta:
    description = "padded form of MSXML2.HTTP"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"

  strings:
$a = /M.{0,48}S.{0,48}X.{0,48}M.{0,48}L.{0,48}2.{0,48}\.X.{0,48}M.{0,48}L.{0,48}H.{0,48}T.{0,48}T.{0,48}P.{0,48}/
  condition:
    filesize < 128KB and $a and !a > 32
}

rule obfuscation_base64_str_replace: medium {
  meta:
    description = "creatively hidden forms of the term 'base64'"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"

  strings:
$a = /\wba\ws\we64/
    $b = /\wb\wa\wse\w6\w4/
    $c = /\wba\ws\we\w6\w4/
    $d = /\wb\was\we\w6\w4/
    $e = /\wb\wa\ws\we6\w4/
    $f = /\wb\wa\ws\we\w64/
    $g = "'bas'.'e'.'6'.'4"
    $h = "'ba'.'se'.'6'.'4"
    $i = "'b'.'ase'.'6'.'4"
    $j = "'bas'.'e'.'6'.'4"
  condition:
    any of them
}

rule gzinflate_str_replace: critical {
  meta:
    description = "creatively hidden forms of the term 'gzinflate'"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"

  strings:
$a = /g.z.inf.l.a/
    $b = /g.z.i.n.f.l/
    $c = /g.z.in.f.l/
  condition:
    any of them
}

rule funky_function: critical {
  meta:
    description = "creatively hidden forms of the term 'function'"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"
    filetypes   = "php"

  strings:
$a = "'fu'.'nct'.'ion'"
    $b = "'f'.'unc'.'tion'"
    $c = "'fun'.'nc'.'tion'"
    $d = "'fun'.'ncti'.'on'"
  condition:
    any of them
}
