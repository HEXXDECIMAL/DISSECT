// Migrated from malcontent: privesc/linpeas.yara

rule linpeas: high {
  meta:
    description = "searches for opportunities for privilege escalation"
    confidence  = "0.66"

  strings:
$ref = "linpeas" fullword
  condition:
    $ref
}
