// Migrated from malcontent: anti-static/obfuscation/url.yara

import "math"


rule decode_url_component_char_code: critical {
  meta:
    description = "decodes obfuscated URL components"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$ref          = "decodeURIComponent"
    $charCodeAt   = "charCodeAt"
    $fromCharCode = "fromCharCode"
  condition:
    filesize < 1MB and all of them and (math.abs(@charCodeAt - @ref) <= 128) or (math.abs(@fromCharCode - @ref) <= 128)
}
