// Migrated from malcontent: persist/kernel_module/name.yara

rule lkm_name: medium {
  meta:
    description = "mentions Linux kernel module by name"
    confidence  = "0.66"
    capability  = "CAP_SYS_MODULE"

  strings:
$ko = /[a-z_]{2,12}\.ko/ fullword

    $o_kernel         = "kernel"
    $o_lsmod          = "lsmod"
    $o_rmmod          = "rmmod"
    $o_insmod         = "insmod"
    $o_modprobe       = "modprobe"
    $not_languages_ko = "languages.ko"
  condition:
    $ko and any of ($o*) and none of ($not*)
}
