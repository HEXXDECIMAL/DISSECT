// Migrated from malcontent: discover/system/system_uuid.yara

rule macos_ioplatform_deviceid: medium {
  meta:
    description = "machine unique identifier"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"

  strings:
$ref  = "IOPlatformUUID" fullword
    $ref2 = "DeviceIDInKeychain"
  condition:
    any of them
}
