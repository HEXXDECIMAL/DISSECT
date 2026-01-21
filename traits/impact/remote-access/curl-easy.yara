// Migrated from malcontent: impact/remote_access/curl_easy.yara

rule linux_curl_easy_sysinfo: high {
  meta:
    description = "may use curl_easy to receive remote commands"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$curl_easy = "curl_easy"
    $fopen     = "fopen" fullword
    $fwrite    = "fwrite" fullword
    $system    = "system" fullword
    $unlink    = "unlink" fullword
    $chmod     = "chmod" fullword
    $https     = /https*:\/\/[\w\.\/]{4,32}/
  condition:
    filesize < 100KB and all of them
}
