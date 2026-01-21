// Migrated from malcontent: exfil/stealer/sqlite.yara

rule py_crypto_sqlite_requests: high {
  meta:
    confidence  = "0.66"
    ref         = "objective-see/GravityRAT/Enigma/Enigma"

  strings:
$import   = "import" fullword
    $bCrypto  = "bCrypto" fullword
    $sqlite   = "sqlite" fullword
    $requests = "requests" fullword
  condition:
    all of them
}
