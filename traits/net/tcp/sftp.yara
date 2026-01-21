// Migrated from malcontent: net/tcp/sftp.yara

rule sftp: medium {
  meta:
    description = "Supports sftp (FTP over SSH)"
    capability  = "true"
    confidence  = "0.66"

  strings:
$sftp   = "sftp" fullword
    $ssh    = "ssh" fullword
    $packet = "sshFxpWritePacket" fullword
  condition:
    filesize < 100MB and 2 of them
}
