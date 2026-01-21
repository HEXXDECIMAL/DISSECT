// Migrated from malcontent: data/encoding/audio-pcm.yara

rule pcm: harmless {
  meta:
    confidence  = "0.66"

  strings:
$pcm_mulaw     = "pcm_mulaw" fullword
    $pcm_alaw      = "pcm_mulaw" fullword
    $pcm_s8_planar = "pcm_s8_planar" fullword
  condition:
    any of them
}
