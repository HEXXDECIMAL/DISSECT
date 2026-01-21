// Migrated from malcontent: data/encoding/audio-vorbis.yara

rule vorbisdsp: harmless {
  meta:
    confidence  = "0.66"

  strings:
$vorbisdsp = "vorbisdsp"
  condition:
    any of them
}
