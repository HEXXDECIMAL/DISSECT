// Migrated from malcontent: fs/path/home.yara

rule home_path: low {
  meta:
    description = "references path within /home"
    capability  = "true"
    confidence  = "0.66"

  strings:
$home       = /\/home\/[%\w\.\-\/]{0,64}/
    $not_build  = "/home/build"
    $not_runner = "/home/runner"
  condition:
    $home and none of ($not*)
}
