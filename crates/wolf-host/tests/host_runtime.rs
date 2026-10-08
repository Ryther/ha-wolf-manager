use std::{cell::RefCell, io, rc::Rc, time::Duration};
use wolf_manager_host::{
    host_runtime::{Effects, StartupAdapter},
    host_status::{Output, Tool, Tools},
    lifecycle,
    policy::RootPolicy,
};
fn policy() -> RootPolicy {
    serde_json::from_value(serde_json::json!({"version":1,"pc_id":"fixture","steam_uid":1000,"steam_gid":1000,"libraries":[{"library_id":"primary","steamapps_path":"/fixture/steamapps","container_paths":["/home/steam/Steam/steamapps"]}],"steam_profiles":[{"root":"/fixture","config_vdf":"config/config.vdf","libraryfolders_vdf":["steamapps/libraryfolders.vdf"],"userdata_directory":"userdata","container_userdata_paths":["/home/steam/Steam/userdata"]}],"wolf_config":{"root":"/wolf","relative_path":"config.toml","uid":0,"gid":0},"compose_file":"/wolf/compose.json","service_unit":"wolf.service","container_name":"wolf","image_ref":"ghcr.io/games-on-whales/wolf:stable","backup_root":"/private/backups","state_root":"/private/state","catalog_state_directory":"/private/catalog","broker_secret_file":null,"pull_on_start":true,"pull_timeout_seconds":300,"proton":null,"steam_executables":["/usr/bin/steam"],"steam_runner":{"type":"docker","image":"example.invalid/steam:stable"}})).unwrap()
}
struct Fake {
    events: Rc<RefCell<Vec<String>>>,
    cached: bool,
    wrong_arch: bool,
}
impl Tools for Fake {
    fn run(&mut self, tool: Tool, args: &[&str], timeout: Duration) -> io::Result<Output> {
        assert_eq!(tool, Tool::Docker);
        assert!(timeout <= Duration::from_secs(300));
        self.events.borrow_mut().push(args.join(" "));
        if args.first() == Some(&"pull") {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture registry unavailable",
            ));
        }
        if args.first() == Some(&"image") {
            return Ok(Output {
                code: Some(if self.cached { 0 } else { 1 }),
                stdout: serde_json::to_vec(&serde_json::json!({"Architecture":if self.wrong_arch {"unrelated-cpu"} else {match std::env::consts::ARCH {"x86_64"=>"amd64","aarch64"=>"arm64",_=>"unsupported"}},"Os":"linux"})).unwrap(),
            });
        }
        if args.get(1) == Some(&"ls") && !args.contains(&"{{.Names}}") {
            return Ok(Output {
                code: Some(0),
                stdout: Vec::new(),
            });
        }
        if args.get(1) == Some(&"ls") {
            return Ok(Output {
                code: Some(0),
                stdout: b"wolf\n".to_vec(),
            });
        }
        if args.get(1) == Some(&"inspect") {
            return Ok(Output {
                code: Some(0),
                stdout: br#"{"State":{"Status":"running","ExitCode":0},"RestartCount":0}"#.to_vec(),
            });
        }
        Ok(Output {
            code: Some(0),
            stdout: Vec::new(),
        })
    }
}
struct Hooks(Rc<RefCell<Vec<String>>>);
impl Effects for Hooks {
    fn prepare(&mut self) -> io::Result<()> {
        self.0.borrow_mut().push("prepare".into());
        Ok(())
    }
    fn restore(&mut self) -> io::Result<()> {
        self.0.borrow_mut().push("restore".into());
        Ok(())
    }
    fn mark_running(&mut self, running: bool) -> io::Result<()> {
        self.0.borrow_mut().push(format!("running:{running}"));
        Ok(())
    }
}
#[test]
fn registry_failure_uses_cached_image_before_cleanup_and_prepare() {
    let p = policy();
    let events = Rc::new(RefCell::new(vec![]));
    let mut adapter = StartupAdapter::new(
        &p,
        Fake {
            events: events.clone(),
            cached: true,
            wrong_arch: false,
        },
        Hooks(events.clone()),
    )
    .unwrap();
    lifecycle::startup(&mut adapter, true).unwrap();
    let events = events.borrow();
    assert!(events[0].starts_with("pull "));
    assert!(events[1].starts_with("image inspect "));
    let cleanup = events.iter().position(|e| e.contains(" down ")).unwrap();
    let prepare = events.iter().position(|e| e == "prepare").unwrap();
    let up = events.iter().position(|e| e.contains(" up ")).unwrap();
    assert!(cleanup > 1 && prepare > cleanup && up > prepare);
    assert_eq!(events.last().unwrap(), "running:true");
}
#[test]
fn missing_cache_refuses_before_any_cleanup_or_steam_writes() {
    let p = policy();
    let events = Rc::new(RefCell::new(vec![]));
    let mut adapter = StartupAdapter::new(
        &p,
        Fake {
            events: events.clone(),
            cached: false,
            wrong_arch: false,
        },
        Hooks(events.clone()),
    )
    .unwrap();
    assert!(lifecycle::startup(&mut adapter, true).is_err());
    assert_eq!(events.borrow().len(), 2);
}
struct OwnedFake {
    events: Rc<RefCell<Vec<String>>>,
    wrong_pc: bool,
    stopped: bool,
}
impl Tools for OwnedFake {
    fn run(&mut self, tool: Tool, args: &[&str], _timeout: Duration) -> io::Result<Output> {
        assert_eq!(tool, Tool::Docker);
        self.events.borrow_mut().push(args.join(" "));
        let id = "a".repeat(64);
        let stdout = if args.get(1) == Some(&"ls") {
            if args.iter().any(|a| a.starts_with("label=")) {
                format!("{id}\n").into_bytes()
            } else {
                Vec::new()
            }
        } else if args.get(1) == Some(&"inspect") {
            serde_json::to_vec(&serde_json::json!({"Id":id,"Config":{"Labels":{"io.ha-wolf-manager.pc":if self.wrong_pc{"other"}else{"fixture"},"io.ha-wolf-manager.owner":"managed-steam-v1"}},"State":{"Status":if self.stopped{"exited"}else{"running"}}})).unwrap()
        } else if args.get(1) == Some(&"stop") {
            self.stopped = true;
            Vec::new()
        } else {
            panic!("unexpected fixed action")
        };
        Ok(Output {
            code: Some(0),
            stdout,
        })
    }
}
#[test]
fn owned_child_stop_revalidates_labels_and_never_removes_storage() {
    let p = policy();
    let events = Rc::new(RefCell::new(vec![]));
    let mut fake = OwnedFake {
        events: events.clone(),
        wrong_pc: false,
        stopped: false,
    };
    wolf_manager_host::host_runtime::stop_owned(&p, &mut fake, Duration::from_secs(30)).unwrap();
    assert!(fake.stopped);
    assert_eq!(
        events
            .borrow()
            .iter()
            .filter(|e| e.contains(" stop "))
            .count(),
        1
    );
    assert!(!events.borrow().iter().any(|e| {
        e.split_whitespace()
            .any(|word| word == "rm" || word == "prune")
    }));
    let events = Rc::new(RefCell::new(vec![]));
    let mut fake = OwnedFake {
        events: events.clone(),
        wrong_pc: true,
        stopped: false,
    };
    assert!(
        wolf_manager_host::host_runtime::stop_owned(&p, &mut fake, Duration::from_secs(30))
            .is_err()
    );
    assert!(!fake.stopped);
    assert!(!events.borrow().iter().any(|e| e.contains(" stop ")));
}
struct WriterFake {
    events: Rc<RefCell<Vec<String>>>,
    rw: bool,
}
impl Tools for WriterFake {
    fn run(&mut self, _tool: Tool, args: &[&str], _timeout: Duration) -> io::Result<Output> {
        self.events.borrow_mut().push(args.join(" "));
        let id = "b".repeat(64);
        let stdout = if args.get(1) == Some(&"ls") {
            format!("{id}\n").into_bytes()
        } else {
            serde_json::to_vec(&serde_json::json!({"Id":id,"State":{"Status":"running"},"Mounts":[{"Source":"/fixture","RW":self.rw}]})).unwrap()
        };
        Ok(Output {
            code: Some(0),
            stdout,
        })
    }
}
#[test]
fn unowned_writable_steam_mount_refuses_without_any_container_mutation() {
    let p = policy();
    let events = Rc::new(RefCell::new(vec![]));
    let mut fake = WriterFake {
        events: events.clone(),
        rw: true,
    };
    assert!(
        wolf_manager_host::host_runtime::require_no_container_writers(
            &p,
            &mut fake,
            Duration::from_secs(30)
        )
        .is_err()
    );
    assert_eq!(events.borrow().len(), 2);
    assert!(
        events
            .borrow()
            .iter()
            .all(|e| e.starts_with("container ls ") || e.starts_with("container inspect "))
    );
    let mut fake = WriterFake { events, rw: false };
    wolf_manager_host::host_runtime::require_no_container_writers(
        &p,
        &mut fake,
        Duration::from_secs(30),
    )
    .unwrap();
}

#[test]
fn incompatible_cached_image_refuses_before_cleanup() {
    let p = policy();
    let events = Rc::new(RefCell::new(vec![]));
    let mut adapter = StartupAdapter::new(
        &p,
        Fake {
            events: events.clone(),
            cached: true,
            wrong_arch: true,
        },
        Hooks(events.clone()),
    )
    .unwrap();
    assert!(lifecycle::startup(&mut adapter, true).is_err());
    assert_eq!(events.borrow().len(), 2);
}
