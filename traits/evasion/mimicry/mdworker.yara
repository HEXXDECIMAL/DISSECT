// Migrated from malcontent: evasion/mimicry/mdworker.yara

rule mdworker: medium {
  meta:
    description = "references mdmorker, may masquerade as it on macOS"
    confidence  = "0.66"

  strings:
$ref = "mdworker" fullword
  condition:
    $ref
}

rule mdworker_high: high {
  meta:
    description = "references mdmorker, may masquerade as it on macOS"
    confidence  = "0.66"

  strings:
$ref         = "mdworker" fullword
    $not_program = "@(#)PROGRAM:md"
    $not_proj    = "PROJECT:Spotlight"
  condition:
    $ref and none of ($not*)
}
