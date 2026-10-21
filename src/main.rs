//! uninstall-ctx
//!
//! Right-click an .exe or .lnk -> "Uninstall Program".
//!
//! Usage:
//!   uninstall-ctx.exe <file>                 find + launch the uninstaller for <file>
//!   uninstall-ctx.exe --register [--all-users]    add the context-menu entries
//!   uninstall-ctx.exe --unregister [--all-users]  remove them
//!
//! Built as a GUI-subsystem binary (no console flash), so all feedback is
//! shown through native Windows message boxes.

#![windows_subsystem = "windows"]

#[cfg(not(windows))]
compile_error!("This project only builds for Windows targets.");

use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::ptr::{null, null_mut};

use winreg::enums::*;
use winreg::RegKey;

/// UTF-16, NUL-terminated.
fn wide<S: AsRef<OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

// ───────────────────────────── Native dialogs ─────────────────────────────

mod ui {
    use super::*;

    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, utype: u32) -> i32;
    }

    const MB_OK: u32 = 0x0;
    const MB_YESNO: u32 = 0x4;
    const MB_ICONERROR: u32 = 0x10;
    const MB_ICONQUESTION: u32 = 0x20;
    const MB_ICONINFORMATION: u32 = 0x40;
    const MB_SETFOREGROUND: u32 = 0x10000;
    const MB_TOPMOST: u32 = 0x40000;
    const IDYES: i32 = 6;
    const TITLE: &str = "Uninstall Program";

    fn show(text: &str, flags: u32) -> i32 {
        let t = wide(text);
        let c = wide(TITLE);
        unsafe { MessageBoxW(null_mut(), t.as_ptr(), c.as_ptr(), flags | MB_SETFOREGROUND | MB_TOPMOST) }
    }

    pub fn error(text: &str) {
        show(text, MB_OK | MB_ICONERROR);
    }

    pub fn info(text: &str) {
        show(text, MB_OK | MB_ICONINFORMATION);
    }

    pub fn confirm(text: &str) -> bool {
        show(text, MB_YESNO | MB_ICONQUESTION) == IDYES
    }
}

// ─────────────────────────── .lnk target resolution ───────────────────────────

mod shortcut {
    use super::*;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// Returns the real target for a .lnk, or the path itself for anything else.
    pub fn resolve(path: &Path) -> Option<PathBuf> {
        let is_lnk = path
            .extension()
            .map_or(false, |e| e.eq_ignore_ascii_case("lnk"));
        if !is_lnk {
            return Some(path.to_path_buf());
        }
        // Fast path: parse the binary file directly (no COM, no child process).
        if let Ok(data) = std::fs::read(path) {
            if let Some(p) = parse_lnk(&data) {
                if p.exists() {
                    return Some(p);
                }
            }
        }
        // Slow path: some shortcuts only carry an ID list (no LinkInfo block).
        resolve_via_powershell(path)
    }

    fn u16_at(d: &[u8], o: usize) -> Option<usize> {
        d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
    }

    fn u32_at(d: &[u8], o: usize) -> Option<usize> {
        d.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }

    fn cstr_ansi(d: &[u8], o: usize) -> Option<String> {
        let s = d.get(o..)?;
        let end = s.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&s[..end]).into_owned())
    }

    fn cstr_utf16(d: &[u8], o: usize) -> Option<String> {
        let s = d.get(o..)?;
        let mut units = Vec::new();
        for ch in s.chunks_exact(2) {
            let u = u16::from_le_bytes([ch[0], ch[1]]);
            if u == 0 {
                break;
            }
            units.push(u);
        }
        Some(String::from_utf16_lossy(&units))
    }

    /// Minimal MS-SHLLINK parser: extracts LocalBasePath + CommonPathSuffix.
    fn parse_lnk(d: &[u8]) -> Option<PathBuf> {
        if u32_at(d, 0)? != 0x4C {
            return None; // bad header size
        }
        let flags = u32_at(d, 0x14)?;
        let mut off = 0x4C;
        if flags & 0x1 != 0 {
            // HasLinkTargetIDList: u16 size followed by the list
            off += 2 + u16_at(d, off)?;
        }
        if flags & 0x2 == 0 {
            return None; // no LinkInfo
        }
        let li = off;
        let header_size = u32_at(d, li + 4)?;
        let li_flags = u32_at(d, li + 8)?;
        if li_flags & 1 == 0 {
            return None; // no local path (network target)
        }
        let base_off = u32_at(d, li + 16)?;
        let suffix_off = u32_at(d, li + 24)?;

        let (base, suffix) = if header_size >= 0x24 && u32_at(d, li + 28)? != 0 {
            let bu = u32_at(d, li + 28)?;
            let su = u32_at(d, li + 32)?;
            (
                cstr_utf16(d, li + bu)?,
                if su != 0 { cstr_utf16(d, li + su)? } else { String::new() },
            )
        } else {
            (
                cstr_ansi(d, li + base_off)?,
                if suffix_off != 0 { cstr_ansi(d, li + suffix_off)? } else { String::new() },
            )
        };

        if base.is_empty() {
            return None;
        }
        Some(if suffix.is_empty() {
            PathBuf::from(base)
        } else {
            PathBuf::from(base).join(suffix)
        })
    }

    fn resolve_via_powershell(lnk: &Path) -> Option<PathBuf> {
        let script = format!(
            "(New-Object -ComObject WScript.Shell).CreateShortcut('{}').TargetPath",
            lnk.to_string_lossy().replace('\'', "''")
        );
        let out = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() {
            return None;
        }
        let p = PathBuf::from(s);
        p.exists().then_some(p)
    }
}

// ───────────────────── Registry search + uninstaller launch ─────────────────────

mod uninstall {
    use super::*;

    const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    pub struct Entry {
        pub name: String,
        pub command: String,
    }

    /// Expand %VAR% sequences.
    fn expand_env(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find('%') {
            out.push_str(&rest[..i]);
            let after = &rest[i + 1..];
            if let Some(j) = after.find('%') {
                match std::env::var(&after[..j]) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(&after[..j]);
                        out.push('%');
                    }
                }
                rest = &after[j + 1..];
            } else {
                out.push('%');
                rest = after;
            }
        }
        out.push_str(rest);
        out
    }

    /// Lowercase, no quotes, backslashes only, no trailing slash, no \\?\ prefix.
    fn norm(s: &str) -> String {
        let s = s.trim().trim_matches('"').replace('/', "\\");
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
        s.trim_end_matches('\\').to_lowercase()
    }

    /// Lowercase alphanumerics only (for fuzzy name comparison).
    fn squash(s: &str) -> String {
        s.chars()
            .filter(|c| c.is_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect()
    }

    fn is_within(dir: &str, parent: &str) -> bool {
        dir == parent || dir.starts_with(&format!("{parent}\\"))
    }

    /// Reject roots like "C:\" or "C:\Program Files" which would match everything.
    fn is_specific(dir: &str) -> bool {
        Path::new(dir)
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count()
            >= 2
    }

    /// `"C:\a\b.exe",0` / `C:\a\b.exe,-101` -> `C:\a\b.exe`
    fn strip_icon_index(s: &str) -> String {
        let s = s.trim();
        if let Some(r) = s.strip_prefix('"') {
            if let Some(end) = r.find('"') {
                return r[..end].to_string();
            }
        }
        if let Some((left, right)) = s.rsplit_once(',') {
            if right.trim().parse::<i32>().is_ok() {
                return left.to_string();
            }
        }
        s.to_string()
    }

    /// Split an uninstall command line into (program, raw argument string).
    fn split_command(cmd: &str) -> (String, String) {
        let cmd = cmd.trim();
        if let Some(r) = cmd.strip_prefix('"') {
            if let Some(end) = r.find('"') {
                return (r[..end].to_string(), r[end + 1..].trim_start().to_string());
            }
        }
        // Unquoted path that may contain spaces: cut after the first ".exe".
        if let Some(i) = cmd.to_ascii_lowercase().find(".exe") {
            let end = i + 4;
            return (cmd[..end].to_string(), cmd[end..].trim_start().to_string());
        }
        match cmd.split_once(' ') {
            Some((p, a)) => (p.to_string(), a.trim_start().to_string()),
            None => (cmd.to_string(), String::new()),
        }
    }

    /// Find the best-matching uninstall entry for `exe`.
    ///
    /// Scoring (highest wins, ties broken by path specificity):
    ///   100  DisplayIcon points at this exe
    ///    80  InstallLocation contains this exe
    ///    60  the uninstaller lives in a folder that contains this exe
    ///    50  DisplayName == exe name        40  DisplayName contains exe name
    pub fn find(exe: &Path) -> Option<Entry> {
        let target = norm(&exe.to_string_lossy());
        let exe_dir = norm(&exe.parent()?.to_string_lossy());
        let stem = squash(&exe.file_stem()?.to_string_lossy());

        let mut best: Option<((u32, usize), Entry)> = None;

        for (hive, view) in [
            (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
            (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
            (HKEY_CURRENT_USER, KEY_WOW64_64KEY),
            (HKEY_CURRENT_USER, KEY_WOW64_32KEY),
        ] {
            let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(UNINSTALL_KEY, KEY_READ | view)
            else {
                continue;
            };

            for sub in root.enum_keys().flatten() {
                let Ok(app) = root.open_subkey_with_flags(&sub, KEY_READ | view) else {
                    continue;
                };
                let get = |n: &str| -> Option<String> {
                    app.get_value::<String, _>(n)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                };

                // Prefer the interactive uninstaller; fall back to the quiet one.
                let Some(cmd) = get("UninstallString").or_else(|| get("QuietUninstallString")) else {
                    continue;
                };

                let mut rank = (0u32, 0usize);

                if let Some(icon) = get("DisplayIcon") {
                    if norm(&strip_icon_index(&expand_env(&icon))) == target {
                        rank = rank.max((100, 0));
                    }
                }
                if let Some(loc) = get("InstallLocation") {
                    let l = norm(&expand_env(&loc));
                    if is_specific(&l) && is_within(&exe_dir, &l) {
                        rank = rank.max((80, l.len()));
                    }
                }
                let (prog, _) = split_command(&expand_env(&cmd));
                if let Some(d) = Path::new(&prog).parent() {
                    let d = norm(&d.to_string_lossy());
                    if is_specific(&d) && is_within(&exe_dir, &d) {
                        rank = rank.max((60, d.len()));
                    }
                }
                let name = get("DisplayName").unwrap_or_else(|| sub.clone());
                let n = squash(&name);
                if stem.len() >= 3 && n == stem {
                    rank = rank.max((50, 0));
                } else if stem.len() >= 4 && n.contains(&stem) {
                    rank = rank.max((40, 0));
                }

                if rank.0 >= 40 && best.as_ref().map_or(true, |(r, _)| rank > *r) {
                    best = Some((rank, Entry { name, command: cmd }));
                }
            }
        }
        best.map(|(_, e)| e)
    }

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut c_void,
            op: *const u16,
            file: *const u16,
            params: *const u16,
            dir: *const u16,
            show: i32,
        ) -> *mut c_void;
    }

    /// Launch the uninstall command (detached). Falls back to a UAC prompt
    /// if the uninstaller requires elevation (error 740).
    pub fn run(command: &str) -> io::Result<()> {
        let (prog, args) = split_command(&expand_env(command));
        let mut c = Command::new(&prog);
        if !args.is_empty() {
            c.raw_arg(&args); // pass arguments verbatim, exactly as stored
        }
        if let Some(dir) = Path::new(&prog).parent().filter(|d| d.is_dir()) {
            c.current_dir(dir);
        }
        match c.spawn() {
            Ok(_) => Ok(()),
            Err(e) if e.raw_os_error() == Some(740) => elevate(&prog, &args),
            Err(e) => Err(e),
        }
    }

    fn elevate(prog: &str, args: &str) -> io::Result<()> {
        let op = wide("runas");
        let file = wide(prog);
        let params = wide(args);
        let r = unsafe {
            ShellExecuteW(
                null_mut(),
                op.as_ptr(),
                file.as_ptr(),
                if args.is_empty() { null() } else { params.as_ptr() },
                null(),
                1, // SW_SHOWNORMAL
            )
        };
        let code = r as isize;
        if code > 32 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("elevation failed or was cancelled (ShellExecute code {code})"),
            ))
        }
    }
}

// ───────────────────────── Context-menu (un)registration ─────────────────────────

mod setup {
    use super::*;

    const CLASSES: [&str; 2] = ["lnkfile", "exefile"];
    const VERB: &str = "UninstallProgram";

    fn root(all_users: bool) -> RegKey {
        RegKey::predef(if all_users { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER })
    }

    pub fn register(all_users: bool) -> io::Result<()> {
        let exe = std::env::current_exe()?;
        let exe = exe.to_string_lossy().trim_start_matches(r"\\?\").to_string();
        let root = root(all_users);

        for class in CLASSES {
            let base = format!(r"Software\Classes\{class}\shell\{VERB}");
            let (key, _) = root.create_subkey(&base)?;
            key.set_value("", &"Uninstall Program")?;
            key.set_value("Icon", &format!("\"{exe}\",0"))?;
            let (cmd, _) = key.create_subkey("command")?;
            cmd.set_value("", &format!("\"{exe}\" \"%1\""))?;
        }
        Ok(())
    }

    pub fn unregister(all_users: bool) -> io::Result<()> {
        let root = root(all_users);
        for class in CLASSES {
            let base = format!(r"Software\Classes\{class}\shell\{VERB}");
            match root.delete_subkey_all(&base) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────── main ───────────────────────────────────

const USAGE: &str = "Right-click an .exe or .lnk and choose \"Uninstall Program\".\n\n\
Setup:\n  uninstall-ctx.exe --register [--all-users]\n  uninstall-ctx.exe --unregister [--all-users]\n\n\
--all-users writes to HKLM and requires an elevated prompt.";

fn uninstall_for(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("File not found:\n{}", path.display()));
    }
    let exe = shortcut::resolve(path)
        .ok_or_else(|| format!("Could not resolve the shortcut target of:\n{}", path.display()))?;
    if !exe.exists() {
        return Err(format!("The target no longer exists:\n{}", exe.display()));
    }
    let entry = uninstall::find(&exe).ok_or_else(|| {
        format!(
            "No uninstaller was found for:\n{}\n\nPortable programs and some installers don't register one.",
            exe.display()
        )
    })?;
    if !ui::confirm(&format!("Uninstall \"{}\"?\n\nMatched from:\n{}", entry.name, exe.display())) {
        return Ok(());
    }
    uninstall::run(&entry.command).map_err(|e| {
        format!(
            "Could not start the uninstaller for \"{}\":\n{}\n\nCommand:\n{}",
            entry.name, e, entry.command
        )
    })
}

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let all_users = args.iter().any(|a| a == "--all-users");

    match args.first().and_then(|a| a.to_str()) {
        None | Some("--help") | Some("-h") => ui::info(USAGE),
        Some("--register") => match setup::register(all_users) {
            Ok(()) => ui::info("Context-menu entry registered.\n\nOn Windows 11 it appears under \"Show more options\"."),
            Err(e) => ui::error(&format!("Registration failed:\n{e}")),
        },
        Some("--unregister") => match setup::unregister(all_users) {
            Ok(()) => ui::info("Context-menu entry removed."),
            Err(e) => ui::error(&format!("Unregistration failed:\n{e}")),
        },
        _ => {
            if let Err(msg) = uninstall_for(&PathBuf::from(&args[0])) {
                ui::error(&msg);
            }
        }
    }
}
