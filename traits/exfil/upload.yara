// Migrated from malcontent: exfil/upload.yara

rule pcloud_storage_user: medium {
  meta:
    description = "uses PCloud for cloud storage"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$pcloud = "api.pcloud.com"
  condition:
    any of them
}

rule google_drive: medium {
  meta:
    description = "References known file hosting site"
    confidence  = "0.66"
    ref         = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_high.yar#L1001"

  strings:
$d_gdrive = /drive.google.com[\/\?\w\=]{0,64}/
  condition:
    any of ($d_*)
}

rule yandex_disk_user: high {
  meta:
    description = "uses Yandex for cloud storage"
    confidence  = "0.66"

  strings:
$yandex = "cloud-api.yandex.net/v1/disk"
  condition:
    any of them
}

rule dropbox_disk_user: medium {
  meta:
    description = "uses DropBox for cloud storage"
    confidence  = "0.66"

  strings:
$dropbox = "dropboxapi.com"
    $Dropbox = "Dropbox"
  condition:
    any of them
}

rule google_drive_uploader: high {
  meta:
    description = "uploads content to Google Drive"
    confidence  = "0.66"

  strings:
$guploader = "x-guploader-client-info"
  condition:
    any of them
}

rule google_docs_uploader: high {
  meta:
    description = "uploads content to Google Drive"
    confidence  = "0.66"

  strings:
$writely = "www.google.com/accounts/ServiceLogin?service=writely"
  condition:
    any of them
}

rule file_io_uploader: high {
  meta:
    description = "uploads content to file.io"
    confidence  = "0.66"

  strings:
$file_io = "file.io" fullword
    $POST    = "POST" fullword
    $Post    = "post" fullword
  condition:
    $file_io and any of ($P*)
}

rule transfer_file: low {
  meta:
    description = "transfers files"
    confidence  = "0.66"

  strings:
$transfer = "transfer file"
  condition:
    any of them
}

rule upload_file: medium {
  meta:
    description = "uploads files"
    confidence  = "0.66"

  strings:
$transfer = "upload file"
    $upload2  = /filesUploa[a-z]{0,6}/
  condition:
    any of them
}
