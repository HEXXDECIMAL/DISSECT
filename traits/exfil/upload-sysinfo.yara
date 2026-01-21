// Migrated from malcontent: exfil/upload_sysinfo.yara

rule sw_vers_and_libcurl: medium {
  meta:
    description = "fetches macOS system version and uses libcurl"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$sw_vers = "sw_vers" fullword
    $bin_zsh = "libcurl"
  condition:
    all of them
}

rule macos_curl_easy_sysinfo: high {
  meta:
    description = "fetches macOS system information and uses curl_easy"
    confidence  = "0.66"

  strings:
$e1        = "IOPlatformExpertDevice" fullword
    $e2        = "IOPlatformSerialNumber"
    $e3        = "ProductVersion"
    $e4        = "ProductBuildVersion"
    $curl_easy = "curl_easy"
  condition:
    all of them
}
