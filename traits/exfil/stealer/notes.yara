// Migrated from malcontent: exfil/stealer/notes.yara

rule stickies: critical {
  meta:
    description = "steals the contents of macos Stickies application"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$note_group = "group.com.apple.notes"
    $note_other = "NoteStore.sqlite"
    $upload     = "upload"
  condition:
    all of them
}
