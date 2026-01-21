// Migrated from malcontent: exfil/curl_post.yara

rule curl_post: medium {
  meta:
    description = "uploads content using curl"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$curl  = "curl" fullword
    $post  = "-X POST"
    $https = "https://"
    $http  = "http://"
  condition:
    filesize < 8KB and $curl and $post and any of ($http*)
}
