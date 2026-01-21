// Migrated from malcontent: c2/addr/tor_onion.yara

rule hardcoded_onion: high {
  meta:
    description = "Contains hardcoded TOR onion address"
    mbc         = "C0001"
    confidence  = "0.66"

  strings:
$ref        = /[a-z0-9]{56}\.onion/
    $not_listen = "listen.onion"
  condition:
    $ref and none of ($not*)
}
