// Migrated from malcontent: impact/ui/parses-arguments.yara

rule argparse: harmless {
  meta:
    description = "parse command-line arguments"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$ref  = "argparse" fullword
    $ref2 = "optarg" fullword
    $ref3 = "getopt" fullword
    $ref4 = "getopts" fullword
  condition:
    any of them
}
