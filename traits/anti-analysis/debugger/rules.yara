// Debugger Detection - YARA Rules
// MBC: OB0001 → B0001

rule ptrace_self_attach {
  meta:
    description = "Anti-debugging via ptrace self-attachment"
    trait_id = "ptrace"
    criticality = "high"
    mbc = "B0001.m01"
    attack = "T1622"

  strings:
    $ptrace = "ptrace" ascii
    $traceme = "PTRACE_TRACEME" ascii
    $deny = "PT_DENY_ATTACH" ascii
    $getpid = "getpid" ascii

  condition:
    $ptrace and ($traceme or $deny) and $getpid
}

rule windows_debugger_checks {
  meta:
    description = "Multiple Windows debugger detection methods"
    trait_id = "win-isdebuggerpresent"
    criticality = "high"
    mbc = "B0001"
    attack = "T1622"

  strings:
    $api1 = "IsDebuggerPresent" wide ascii
    $api2 = "CheckRemoteDebuggerPresent" wide ascii
    $api3 = "NtQueryInformationProcess" wide ascii

  condition:
    2 of them
}
