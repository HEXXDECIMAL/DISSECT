// Migrated from malcontent: fs/path/home-config.yara

rule home_config_path {
  meta:
    description = "path reference within ~/.config"
    capability  = "true"
    confidence  = "0.66"

  strings:
$resolv = /[\$\~\w\/]{0,10}\.config\/[ \w\/]{1,64}/
  condition:
    any of them
}
