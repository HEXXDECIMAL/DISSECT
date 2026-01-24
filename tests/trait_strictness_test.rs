use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_hostile_trait_downgrade_warning() {
    let temp_dir = TempDir::new().unwrap();

    // 1. Atomic trait marked HOSTILE
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir(&traits_dir).unwrap();

    let atomic_yaml = r##"
traits:
  - id: hostile/atomic
    description: "Short"
    criticality: hostile
    condition:
      type: symbol
      pattern: "evil_func"
"##;
    fs::write(traits_dir.join("atomic.yaml"), atomic_yaml).unwrap();

    // 2. Composite trait marked HOSTILE but with only 1 condition
    let composite_yaml = r##"
composite_rules:
  - id: hostile/weak-composite
    description: "Composite trait marked HOSTILE but too weak"
    criticality: hostile
    requires_all:
      - type: symbol
        pattern: "func1"
"##;
    fs::write(traits_dir.join("composite.yaml"), composite_yaml).unwrap();

    // 3. Composite trait marked HOSTILE with 3 conditions but NO file_type filter (FileType::All is default)
    let composite_no_filter_yaml = r##"
composite_rules:
  - id: hostile/no-filter
    description: "Composite trait marked HOSTILE but no file_type filter"
    criticality: hostile
    requires_all:
      - type: symbol
        pattern: "func1"
      - type: symbol
        pattern: "func2"
      - type: symbol
        pattern: "func3"
"##;
    fs::write(traits_dir.join("no_filter.yaml"), composite_no_filter_yaml).unwrap();

    let target_file = temp_dir.path().join("target.sh");
    fs::write(&target_file, "#!/bin/bash\nevil_func\n").unwrap();

    // Run dissect pointing to the temp traits directory
    // We need to set the working directory so it finds "traits"
    assert_cmd::cargo_bin_cmd!("dissect")
        .current_dir(temp_dir.path())
        .args(["analyze", target_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Downgrading to SUSPICIOUS").count(3))
        .stderr(predicate::str::contains("lacks an MBC or MITRE ATT&CK mapping").count(0))
        .stderr(predicate::str::contains("overly short description"))
        .stderr(predicate::str::contains("targets all platforms and file types").count(0))
        .stderr(predicate::str::contains("hostile/atomic"))
        .stderr(predicate::str::contains("hostile/weak-composite"))
        .stderr(predicate::str::contains("hostile/no-filter"));
}

#[test]
fn test_hostile_trait_valid() {
    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir(&traits_dir).unwrap();

    let valid_yaml = r##"
composite_rules:
  - id: hostile/valid
    description: "Valid HOSTILE trait with enough context"
    criticality: hostile
    mbc: B0001
    file_types: [shell]
    requires_all:
      - type: symbol
        pattern: "func1"
      - type: symbol
        pattern: "func2"
      - type: symbol
        pattern: "func3"
"##;
    fs::write(traits_dir.join("valid.yaml"), valid_yaml).unwrap();

    let target_file = temp_dir.path().join("target.sh");
    fs::write(&target_file, "#!/bin/bash\n# dummy\n").unwrap();

    // Should NOT show downgrade warning for the valid rule
    assert_cmd::cargo_bin_cmd!("dissect")
        .current_dir(temp_dir.path())
        .args(["analyze", target_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Downgrading to SUSPICIOUS").count(0))
        .stderr(predicate::str::contains("lacks an MBC or MITRE ATT&CK mapping").count(0));
}

#[test]
fn test_suspicious_trait_no_mapping_no_warning() {
    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir(&traits_dir).unwrap();

    let suspicious_yaml = r##"
traits:
  - id: suspicious/no-mapping
    description: "Suspicious trait with no mapping"
    criticality: suspicious
    condition:
      type: symbol
      pattern: "some_func"
"##;
    fs::write(traits_dir.join("suspicious.yaml"), suspicious_yaml).unwrap();

    let target_file = temp_dir.path().join("target.sh");
    fs::write(&target_file, "#!/bin/bash\n# dummy\n").unwrap();

    // Should NOT show warning for SUSPICIOUS traits anymore
    assert_cmd::cargo_bin_cmd!("dissect")
        .current_dir(temp_dir.path())
        .args(["analyze", target_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("lacks an MBC or MITRE ATT&CK mapping").count(0))
        .stderr(predicate::str::contains("targets all platforms and file types").count(0));
}
