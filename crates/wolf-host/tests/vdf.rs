use wolf_manager_host::vdf::Document;
#[test]
fn targeted_edit_preserves_unowned_comments_and_entries() {
    let input = "// user comment\n\"Root\" {\n \"untouched\"  \"literal\\\\value\" // keep\n \"apps\" { \"42\" { \"LaunchOptions\" \"old\" \"Other\" \"keep\" } }\n}\n";
    let mut doc = Document::parse(input).unwrap();
    doc.set(&["Root", "apps", "42", "LaunchOptions"], "ENV=1 %command%")
        .unwrap();
    assert_eq!(doc.text(), input.replace("\"old\"", "\"ENV=1 %command%\""));
    assert_eq!(
        doc.get(&["root", "apps", "42", "LaunchOptions"]).unwrap(),
        Some("ENV=1 %command%".into())
    );
}
#[test]
fn creates_missing_path_and_escapes_roundtrip() {
    let mut doc = Document::parse("\"Root\" { \"other\" \"keep\" }\n").unwrap();
    doc.set(
        &["Root", "apps", "42", "LaunchOptions"],
        "a \"quoted\" \\ path",
    )
    .unwrap();
    assert_eq!(
        doc.get(&["Root", "apps", "42", "LaunchOptions"]).unwrap(),
        Some("a \"quoted\" \\ path".into())
    );
    doc.remove(&["Root", "apps", "42"]).unwrap();
    assert_eq!(doc.get(&["Root", "other"]).unwrap(), Some("keep".into()));
    assert_eq!(
        doc.get(&["Root", "apps", "42", "LaunchOptions"]).unwrap(),
        None
    );
}
#[test]
fn malformed_or_ambiguous_selected_paths_are_refused() {
    assert!(Document::parse("\"Root\" { \"broken\"").is_err());
    let mut doc = Document::parse("\"Root\" { \"a\" \"one\" \"A\" \"two\" }").unwrap();
    let before = doc.text().to_owned();
    assert!(doc.set(&["Root", "a"], "new").is_err());
    assert_eq!(doc.text(), before);
    let deep = format!("{}{}", "\"x\"{".repeat(80), "}".repeat(80));
    assert!(Document::parse(&deep).is_err());
}
