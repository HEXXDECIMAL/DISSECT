// Migrated from malcontent: impact/ransom/fernet_listdir.yara

rule fernet_walker: high {
  meta:
    description = "walks filesystem, encrypts content using Fernet"
    mbc         = "OB0010"
    attack      = "T1486"
    confidence  = "0.66"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "py"

  strings:
$walk    = /\w{0,2}\.walk[\(\w\)]{1,16}/
    $fernet  = /Fernet[\(\w\)]{1,16}/
    $encrypt = /\w{1,16}.encrypt/
  condition:
    filesize < 65535 and all of them
}

rule fernet_locker: critical {
  meta:
    description = "walks filesystem, encrypts and deletes content using Fernet"
    confidence  = "0.66"
    ref         = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    filetypes   = "py"

  strings:
$walk     = /\w{0,2}\.walk[\(\w\)]{1,16}/
    $fernet   = /Fernet[\(\w\)]{1,16}/
    $encrypt  = /\w{1,16}.encrypt/
    $seek     = "seek(0)"
    $write    = "write("
    $truncate = "truncate("
  condition:
    filesize < 65535 and all of them
}
