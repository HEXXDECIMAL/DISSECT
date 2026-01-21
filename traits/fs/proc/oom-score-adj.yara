// Migrated from malcontent: fs/proc/oom_score_adj.yara

rule oom_score_adj: harmless {
  meta:
    description = "access OOM (out-of-memory) settings"
    confidence  = "0.66"
    capability  = "CAP_SYS_RESOURCE"

  strings:
$ref = "oom_score_adj" fullword
  condition:
    any of them
}
