// Migrated from malcontent: net/ip/ipp-request.yara

rule ipp_request {
  meta:
    description = "Makes IPP (Internet Printing Protocol) requests"
    mbc         = "C0001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref  = "ippPort"
    $ref2 = "ipp://"
  condition:
    any of them
}
