// Migrated from malcontent: anti-static/xor/xor-table.yara

rule xor_table: harmless {
  meta:
    description = "Contains a table that may be used for XOR decryption"
    confidence  = "0.66"

  strings:
$ref = "56789abcdefghijklmnopqrstuvwxyzABCDE"
  condition:
    any of them
}
