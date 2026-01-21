// Migrated from malcontent: net/tcp/grpc.yara

rule grpc {
  meta:
    description = "Uses the gRPC Remote Procedure Call framework"
    capability  = "true"
    confidence  = "0.66"

  strings:
$gRPC = "gRPC" fullword
  condition:
    any of them
}
