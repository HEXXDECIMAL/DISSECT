// Migrated from malcontent: net/ip/sunrpc.yara

rule sunrpc: medium {
  meta:
    description = "Uses SunRPC / XDR"
    mbc         = "C0001"
    confidence  = "0.66"

  strings:
$ref  = "xdr_bytes" fullword
    $ref2 = "Incompatible versions of RPC"
  condition:
    any of them
}
