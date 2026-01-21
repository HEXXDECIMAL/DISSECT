// Migrated from malcontent: exfil/stealer/camera.yara

rule macos_screen_stealer: high macos {
  meta:
    description = "may steal screenshots"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$captureScreen = "captureScreen" fullword
    $image         = "CGImageDestinationAddImage" fullword
  condition:
    filesize < 50KB and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178) and any of them
}
