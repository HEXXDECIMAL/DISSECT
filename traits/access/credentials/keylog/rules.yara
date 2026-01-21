// Keylogging Detection - YARA Rules
// MBC: OB0005 → B0015

rule windows_hook {
  meta:
    description = "Windows keyboard hooking via SetWindowsHookEx"
    trait_id = "windows-hook"
    criticality = "high"
    mbc = "B0015.001"
    attack = "T1056.001"

  strings:
    $api = "SetWindowsHookEx" wide ascii
    $wh_keyboard = { 00 00 00 0D }  // WH_KEYBOARD_LL = 13

  condition:
    $api and $wh_keyboard
}

rule linux_input {
  meta:
    description = "Direct access to Linux input devices"
    trait_id = "linux-input"
    criticality = "high"
    mbc = "B0015"
    attack = "T1056.001"

  strings:
    $path = "/dev/input/event" ascii
    $ioctl = "EVIOCGRAB" ascii

  condition:
    all of them
}
