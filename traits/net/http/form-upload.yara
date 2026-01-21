// Migrated from malcontent: net/http/form-upload.yara

rule http_form_upload: medium {
  meta:
    description = "upload content via HTTP form"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$content_form = "application/x-www-form-urlencoded"
    $content_json = "application/json"
    $POST         = "POST" fullword
    $POST2        = "post" fullword
  condition:
    any of ($POST*) and any of ($content*)
}
