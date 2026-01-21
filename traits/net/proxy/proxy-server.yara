// Migrated from malcontent: net/proxy/proxy_server.yara

rule nps_tunnel: critical {
  meta:
    description = "Uses NPS, a intranet penetration proxy server"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref1 = ".LoadTaskFromJsonFile"
    $ref2 = ".LoadHostFromJsonFile"
  condition:
    all of them
}
