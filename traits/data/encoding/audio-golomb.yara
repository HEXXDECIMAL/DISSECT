// Migrated from malcontent: data/encoding/audio-golomb.yara

rule golumb_vlc: harmless {
  meta:
    confidence  = "0.66"

  strings:
$golomb_vlc = "golomb_vlc"
  condition:
    any of them
}
