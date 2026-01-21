// Migrated from malcontent: discover/cloud/google-docs.yara

rule google_docs_user: high {
  meta:
    mbc         = "E1580"
    attack      = "T1580"
    confidence  = "0.66"

  strings:
$writely   = "www.google.com/accounts/ServiceLogin?service=writely"
    $guploader = "x-guploader-client-info: mechanism=scotty"
  condition:
    any of them
}
