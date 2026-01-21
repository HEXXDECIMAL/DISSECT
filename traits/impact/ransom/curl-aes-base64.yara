// Migrated from malcontent: impact/ransom/curl_aes_base64.yara

rule curl_base64_aes: medium {
  meta:
    description = "uses curl_easy, base64, and removes files"
    mbc         = "OB0010"
    attack      = "T1486"
    confidence  = "0.66"

  strings:
$curl_easy = "curl_easy_"
    $aes_key   = "aes_key"
    $base64    = "base64"
    $unlink    = "unlink" fullword
  condition:
    filesize < 100KB and all of them
}
