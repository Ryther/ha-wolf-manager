//! Root-owned Steam runner templates; catalogue titles are data, never commands.
use std::{collections::BTreeMap, io};
use wolf_core::{AppId, CatalogAttributes, Settings};
fn invalid() -> io::Error {
    io::Error::other("invalid generated application template")
}
fn block(app: toml::Table) -> io::Result<String> {
    let profile = toml::Table::from_iter([(
        "apps".into(),
        toml::Value::Array(vec![toml::Value::Table(app)]),
    )]);
    let root = toml::Table::from_iter([(
        "profiles".into(),
        toml::Value::Array(vec![toml::Value::Table(profile)]),
    )]);
    // The profile header belongs to the existing target profile, not a new profile.
    let text = toml::to_string(&root).map_err(|_| invalid())?;
    let remainder = text.strip_prefix("[[profiles]]\n").ok_or_else(invalid)?;
    Ok(remainder.to_owned())
}
pub fn generate(
    settings: &Settings,
    catalog: &BTreeMap<AppId, CatalogAttributes>,
    template: &toml::Table,
) -> io::Result<(String, String)> {
    settings.validate().map_err(|_| invalid())?;
    if template.get("type").and_then(toml::Value::as_str) != Some("docker")
        || template
            .get("image")
            .and_then(toml::Value::as_str)
            .is_none()
    {
        return Err(invalid());
    }
    let mut games = String::new();
    for (id, game) in &settings.games {
        if !game.direct_launch {
            continue;
        }
        let Some(entry) = catalog.get(id) else {
            continue;
        };
        entry.validate().map_err(|_| invalid())?;
        if entry.app_id != *id {
            return Err(invalid());
        }
        let mut runner = template.clone();
        let mut env = match runner.get("env") {
            None => vec![],
            Some(value) => value.as_array().ok_or_else(invalid)?.clone(),
        };
        if env.iter().any(|value| value.as_str().is_none()) {
            return Err(invalid());
        }
        env.retain(|value| !value.as_str().unwrap().starts_with("STEAM_STARTUP_FLAGS="));
        env.push(toml::Value::String(format!(
            "STEAM_STARTUP_FLAGS=steam://rungameid/{id}"
        )));
        runner.insert("env".into(), toml::Value::Array(env));
        let app = toml::Table::from_iter([
            ("title".into(), toml::Value::String(entry.name.clone())),
            (
                "icon_png_path".into(),
                toml::Value::String(entry.cover_url.clone()),
            ),
            (
                "start_virtual_compositor".into(),
                toml::Value::Boolean(true),
            ),
            ("runner".into(), toml::Value::Table(runner)),
        ]);
        games.push_str(&block(app)?);
    }
    let diagnostics = if settings.debug.test_ball {
        let app:toml::Table=toml::from_str(r#"title='Test ball'
icon_png_path='https://raw.githubusercontent.com/games-on-whales/wolf/6a5053b4ebbb19f2c0f3bf1e8fbbd8babf109273/docs/images/test_ball_icon.png'
start_audio_server=false
start_virtual_compositor=false
[audio]
source='audiotestsrc wave=ticks is-live=true'
[runner]
type='process'
run_cmd='sh -c "while :; do sleep 10; done"'
[video]
source='''videotestsrc pattern=ball flip=true is-live=true !
video/x-raw, framerate={fps}/1
'''
"#).map_err(|_|invalid())?;
        block(app)?
    } else {
        String::new()
    };
    Ok((diagnostics, games))
}
