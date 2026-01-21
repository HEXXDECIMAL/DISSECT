// Migrated from malcontent: net/ip/dial.yara

rule dial_shared_screen_discovery: high {
  meta:
    description = "connects to remote screen using dial protocol"
    mbc         = "C0001"
    confidence  = "0.66"

  strings:
$urn_multiscreen = "urn:dial-multiscreen-org:service:dial:1"
    $not_chromium    = "RasterCHROMIUM"
  condition:
    $urn_multiscreen and none of ($not*)
}
