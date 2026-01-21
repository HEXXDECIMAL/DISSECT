// Migrated from malcontent: exfil/http_headers.yara

rule weird_http_headers: high {
  meta:
    description = "references unusual HTTP headers"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$h_cf_id  = "x-amz-cf-id" fullword
    $h_cf_pop = "x-amz-cf-pop" fullword

    $v_fetch = "fetch" fullword
    $v_GET   = "GET" fullword
    $v_POST  = "POST" fullword
    $v_get   = "get" fullword
    $v_post  = "post" fullword
  condition:
    filesize < 1MB and any of ($h*) and any of ($v*)
}
