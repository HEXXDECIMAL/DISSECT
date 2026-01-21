// Migrated from malcontent: credential/keychain/gnome-keyring-daemon.yara

rule gnome_keyring_daemon: medium {
  meta:
    description = "references the gnome-keyring-daemon"
    mbc         = "OB0004"
    attack      = "T1555.001"
    confidence  = "0.66"

  strings:
$ref = /gnome-keyring-da[a-z\-]{0,8}/
  condition:
    $ref
}
