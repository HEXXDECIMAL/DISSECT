// Migrated from malcontent: exfil/stealer/connect_glob_exec.yara

rule http_digest_auth_exec_connector: high {
  meta:
    description = "Uses HTTP Digest auth, runs programs, uses glob"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$d_connect   = "CONNECT"
    $d_digest    = "Digest"
    $d_https     = "https"
    $d_rspauth   = "rspauth"
    $d_exec      = "_exec" fullword
    $d_connect_f = "_connect" fullword
    $d_glob      = "_glob" fullword
  condition:
    all of ($d_*)
}

rule connect_glob_exec_https: medium {
  meta:
    description = "makes HTTPS connections, runs programs, finds files"
    confidence  = "0.66"

  strings:
$d_https     = "https"
    $d_exec      = "_exec" fullword
    $d_connect_f = "_connect" fullword
    $d_glob      = "_glob" fullword
  condition:
    all of ($d_*)
}
