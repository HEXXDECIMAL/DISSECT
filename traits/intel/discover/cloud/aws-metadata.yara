// Migrated from malcontent: discover/cloud/aws-metadata.yara

rule aws_metadata {
  meta:
    description = "References the AWS EC2 metadata token"
    mbc         = "E1580"
    attack      = "T1580"
    confidence  = "0.66"

  strings:
$ref = "X-aws-ec2-metadata-token"
  condition:
    any of them
}
