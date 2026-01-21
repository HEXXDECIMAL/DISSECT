// Migrated from malcontent: evasion/mimicry/fake-var-run-id.yara

rule fake_var_run: medium {
  meta:
    description = "References a likely fake name in /var/run"
    confidence  = "0.66"

  strings:
$ref = /\/var\/run\/daemon[\w\.\-]{0,32}\//
  condition:
    $ref
}
