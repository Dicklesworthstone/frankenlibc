#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc gettext oracle

//! Differential coverage for gettext with real `.mo` catalogs.
//!
//! fl's gettext family returned every msgid untranslated, so a user with a
//! translated locale saw English where glibc showed translations (found by
//! running /usr/bin/* --help under LANG=en_US.UTF-8: dpkg and friends
//! differed). This writes its own catalogs -- Polish (three plural forms,
//! a msgctxt entry), Japanese (one form) and a genuinely ISO-8859-1 German
//! catalog -- binds the same domain in glibc and in fl, and compares
//! dgettext/ngettext/dcgettext results across LANGUAGE chains, plural
//! counts, categories and bind_textdomain_codeset conversions.
//!
//! Skipped, with the reason printed, when the host has no `en_US.UTF-8`
//! (a C-family locale disables translation in both implementations).

use std::ffi::{CStr, CString, c_char, c_int, c_ulong};

use frankenlibc_abi::{locale_abi as fl, unistd_abi as fl_unistd};

unsafe extern "C" {
    #[link_name = "setlocale"]
    fn host_setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
    #[link_name = "bindtextdomain"]
    fn host_bindtextdomain(domain: *const c_char, dir: *const c_char) -> *mut c_char;
    #[link_name = "bind_textdomain_codeset"]
    fn host_bind_textdomain_codeset(domain: *const c_char, codeset: *const c_char) -> *mut c_char;
    #[link_name = "dgettext"]
    fn host_dgettext(domain: *const c_char, msgid: *const c_char) -> *mut c_char;
    #[link_name = "dcgettext"]
    fn host_dcgettext(domain: *const c_char, msgid: *const c_char, category: c_int) -> *mut c_char;
    #[link_name = "dngettext"]
    fn host_dngettext(
        domain: *const c_char,
        msgid: *const c_char,
        msgid_plural: *const c_char,
        n: c_ulong,
    ) -> *mut c_char;
}

/// A little-endian `.mo` image; `entries` are (msgid, translation) bytes.
fn mo_image(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut entries = entries.to_vec();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let n = entries.len();
    let originals = 28;
    let translations = originals + 8 * n;
    let strings = translations + 8 * n;
    let mut head = Vec::new();
    for word in [
        0x9504_12de_u32,
        0,
        n as u32,
        originals as u32,
        translations as u32,
        0,
        0,
    ] {
        head.extend_from_slice(&word.to_le_bytes());
    }
    let mut blob = Vec::new();
    let mut tables = [Vec::new(), Vec::new()];
    for (table, pick) in tables.iter_mut().zip([0usize, 1]) {
        for entry in &entries {
            let s = if pick == 0 { entry.0 } else { entry.1 };
            table.extend_from_slice(&(s.len() as u32).to_le_bytes());
            table.extend_from_slice(&((strings + blob.len()) as u32).to_le_bytes());
            blob.extend_from_slice(s);
            blob.push(0);
        }
    }
    [head, tables[0].clone(), tables[1].clone(), blob].concat()
}

fn write_catalog(root: &std::path::Path, language: &str, image: &[u8]) {
    let dir = root.join(language).join("LC_MESSAGES");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("fltest.mo"), image).unwrap();
}

fn text(ptr: *const c_char) -> Option<String> {
    (!ptr.is_null()).then(|| {
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    })
}

const POLISH_HEADER: &[u8] = b"Content-Type: text/plain; charset=UTF-8\n\
Plural-Forms: nplurals=3; plural=(n==1 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);\n";

#[test]
fn gettext_catalogs_match_host_glibc() {
    let ok = !unsafe { host_setlocale(libc::LC_ALL, c"en_US.UTF-8".as_ptr()) }.is_null();
    if !ok {
        println!(
            "SKIP: host has no en_US.UTF-8 locale (locale -a); translation is off in C locales"
        );
        return;
    }
    assert!(
        !unsafe { fl::setlocale(libc::LC_ALL, c"en_US.UTF-8".as_ptr()) }.is_null(),
        "fl could not load en_US.UTF-8 although the host has it"
    );

    let root = std::env::temp_dir().join(format!("fl_gettext_catalogs_{}", std::process::id()));
    write_catalog(
        &root,
        "pl",
        &mo_image(&[
            (b"", POLISH_HEADER),
            (b"Hello", "Cześć".as_bytes()),
            (
                b"%d file\0%d files",
                "%d plik\0%d pliki\0%d plików".as_bytes(),
            ),
            (b"menu\x04Open", "Otwórz".as_bytes()),
        ]),
    );
    write_catalog(
        &root,
        "ja_JP",
        &mo_image(&[
            (
                b"",
                b"Content-Type: text/plain; charset=UTF-8\nPlural-Forms: nplurals=1; plural=0;\n",
            ),
            (b"%d file\0%d files", "%d ファイル".as_bytes()),
            (b"Only ja", "日本語のみ".as_bytes()),
        ]),
    );
    // Latin-1 bytes: "Grüß dich", "Tschüss «bald»".
    write_catalog(
        &root,
        "de",
        &mo_image(&[
            (b"", b"Content-Type: text/plain; charset=ISO-8859-1\n"),
            (b"Hello", b"Gr\xfc\xdf dich"),
            (b"Bye", b"Tsch\xfcss \xabbald\xbb"),
            (b"%d file\0%d files", b"%d Datei\0%d Dateien"),
        ]),
    );
    let dir = CString::new(root.to_str().unwrap()).unwrap();
    let domain = c"fltest";
    unsafe {
        host_bindtextdomain(domain.as_ptr(), dir.as_ptr());
        fl::bindtextdomain(domain.as_ptr(), dir.as_ptr());
    }

    let msgids: [&CStr; 7] = [
        c"Hello",
        c"Bye",
        c"Only ja",
        c"menu\x04Open",
        c"absent",
        c"",
        c"%d file",
    ];
    let counts: Vec<c_ulong> = (0..=30)
        .chain(100..=125)
        .chain([1_000_001, 4_294_967_297, c_ulong::MAX])
        .collect();
    let mut bad = Vec::new();
    let mut compared = 0usize;
    let mut translated = 0usize;
    let mut check = |what: String, host: *mut c_char, mine: *mut c_char, msgid: *const c_char| {
        compared += 1;
        let (h, m) = (text(host), text(mine));
        if host != msgid.cast_mut() && h.is_some() {
            translated += 1;
        }
        if h != m {
            bad.push(format!("{what}: glibc {h:?}, fl {m:?}"));
        }
    };

    for language in [
        "",
        "pl",
        "pl:ja_JP",
        "ja_JP.UTF-8:pl",
        "de",
        "xx:de",
        "C:pl",
        "pl_PL.UTF-8",
    ] {
        // SAFETY: this test binary runs this single test; nothing else reads
        // the environment concurrently.
        unsafe { std::env::set_var("LANGUAGE", language) };
        for msgid in msgids {
            let host = unsafe { host_dgettext(domain.as_ptr(), msgid.as_ptr()) };
            let mine = unsafe { fl::dgettext(domain.as_ptr(), msgid.as_ptr()) };
            check(
                format!("LANGUAGE={language} dgettext {msgid:?}"),
                host,
                mine,
                msgid.as_ptr(),
            );
            let host = unsafe { host_dcgettext(domain.as_ptr(), msgid.as_ptr(), libc::LC_TIME) };
            let mine =
                unsafe { fl_unistd::dcgettext(domain.as_ptr(), msgid.as_ptr(), libc::LC_TIME) };
            check(
                format!("LANGUAGE={language} LC_TIME {msgid:?}"),
                host,
                mine,
                msgid.as_ptr(),
            );
        }
        for &n in &counts {
            let (one, many) = (c"%d file", c"%d files");
            let host = unsafe { host_dngettext(domain.as_ptr(), one.as_ptr(), many.as_ptr(), n) };
            let mine =
                unsafe { fl_unistd::dngettext(domain.as_ptr(), one.as_ptr(), many.as_ptr(), n) };
            let untranslated = if n == 1 { one } else { many };
            check(
                format!("LANGUAGE={language} ngettext n={n}"),
                host,
                mine,
                untranslated.as_ptr(),
            );
        }
    }

    // Translations re-encoded into a bound codeset (glibc uses //TRANSLIT).
    for (language, codeset) in [("pl", c"ISO-8859-2"), ("de", c"UTF-8"), ("pl", c"ASCII")] {
        unsafe {
            std::env::set_var("LANGUAGE", language);
            host_bind_textdomain_codeset(domain.as_ptr(), codeset.as_ptr());
            fl_unistd::bind_textdomain_codeset(domain.as_ptr(), codeset.as_ptr());
        }
        for msgid in msgids {
            let host = unsafe { host_dgettext(domain.as_ptr(), msgid.as_ptr()) };
            let mine = unsafe { fl::dgettext(domain.as_ptr(), msgid.as_ptr()) };
            check(
                format!("LANGUAGE={language} codeset={codeset:?} {msgid:?}"),
                host,
                mine,
                msgid.as_ptr(),
            );
        }
    }
    unsafe { std::env::remove_var("LANGUAGE") };
    let _ = std::fs::remove_dir_all(&root);

    println!("{compared} lookups compared, {translated} translated by glibc");
    assert!(
        bad.is_empty(),
        "{} divergent:\n{}",
        bad.len(),
        bad.join("\n")
    );
    assert!(
        translated >= 200,
        "only {translated} lookups were translated; catalogs not found?"
    );
}
