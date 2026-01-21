// Migrated from malcontent: c2/client.yara

rule clientID: medium {
  meta:
    description = "contains a client ID"
    confidence  = "0.66"

  strings:
$clientID  = "clientID"
    $client_id = "client_id"
    $clientId  = "clientId"
  condition:
    any of them
}
