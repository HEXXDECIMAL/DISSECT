// Migrated from malcontent: c2/tool_transfer/dropper.yara

rule dropper: medium {
  meta:
    description = "References a 'dropper'"
    mbc         = "OB0013"
    attack      = "T1021"
    confidence  = "0.66"

  strings:
$ref = /[\w]{0,16}[dD]ropper/ fullword
  condition:
    any of them
}

rule dropper_for: high {
  meta:
    description = "References 'dropper for'"
    confidence  = "0.66"

  strings:
$ref = /[dD]ropper for [\w ]{0,32}/ fullword
  condition:
    any of them
}

rule download_and_execute: high {
  meta:
    description = "may download and execute a program"
    confidence  = "0.66"

  strings:
$ref  = "download_and_execute"
    $ref2 = "download_and_exec"
  condition:
    filesize < 1MB and any of them
}
