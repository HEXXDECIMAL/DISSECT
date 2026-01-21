// Migrated from malcontent: data/encoding/json-decode.yara

rule jsondecode {
  meta:
    description = "Decodes JSON messages"
    capability  = "true"
    confidence  = "0.66"

  strings:
$jsond = "JSONDecode"
    $ju    = "json.Unmarshal"
    $jp    = "JSON.parse"
    $jl    = "json.loads"
  condition:
    any of them
}

rule unmarshal_json: harmless {
  meta:
    description = "Decodes JSON messages"
    confidence  = "0.66"

  strings:
$unmarshal = "UnmarshalJSON"
  condition:
    any of them
}
