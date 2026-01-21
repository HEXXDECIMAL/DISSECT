// Migrated from malcontent: process/multithreaded.yara

rule pthread_create {
  meta:
    description = "creates pthreads"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "pthread_create"
    ref         = "https://man7.org/linux/man-pages/man3/pthread_create.3.html"

  strings:
$ref = "pthread_create" fullword
  condition:
    any of them
}

rule py_thread_create: medium {
  meta:
    description = "uses python threading"
    confidence  = "0.66"
    syscall     = "pthread_create"
    ref         = "https://docs.python.org/3/library/threading.html"
    filetypes   = "py"

  strings:
$ref = "threading.Thread"
  condition:
    any of them
}
