// flim settings, shared by flim.exe (launcher) and flim_engine.dll (engine).
// Stored in %APPDATA%\flim\flim.ini, section [flim]:
//   fl_dir     FL Studio 2025 install folder (holds FL64.exe)          - launcher
//   name       user name shown to peers (sanitized, see flim_sanitize_name)
//   server_url last server URL typed into the Connect dialog           - engine
//   server_pw  last password, DPAPI-encrypted for this Windows user (hex)
// The file is created as UTF-16 so the profile API keeps non-ASCII paths and names.
#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <stdio.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

#define FLIM_NAME_MAX  24
#define FLIM_FL_MAJOR  25                   // FL Studio 2025 = file version 25.x
// FL builds the engine has an address table for (engine: k_flBuilds; keep both in sync)
static const wchar_t *const FLIM_FL_BUILDS[] = { L"25.2.5.5319", L"25.2.3.5171", L"25.1.6.4997" };
#define FLIM_FL_BUILDS_TEXT L"25.2.5.5319, 25.2.3.5171, 25.1.6.4997"

static int flimcfg_path(wchar_t *out, int cap) {
    wchar_t dir[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, dir))) return 0;
    swprintf_s(out, cap, L"%s\\flim", dir);
    CreateDirectoryW(out, NULL);
    wcscat_s(out, cap, L"\\flim.ini");
    if (GetFileAttributesW(out) == INVALID_FILE_ATTRIBUTES) {
        HANDLE h = CreateFileW(out, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, "\xff\xfe", 2, &w, NULL); CloseHandle(h); }
    }
    return 1;
}

static void flimcfg_get(const wchar_t *key, wchar_t *out, int cap) {
    wchar_t ini[MAX_PATH];
    out[0] = 0;
    if (flimcfg_path(ini, MAX_PATH)) GetPrivateProfileStringW(L"flim", key, L"", out, cap, ini);
}

static void flimcfg_set(const wchar_t *key, const wchar_t *val) {   // val NULL = delete the key
    wchar_t ini[MAX_PATH];
    if (flimcfg_path(ini, MAX_PATH)) WritePrivateProfileStringW(L"flim", key, val, ini);
}

// Names travel to peers and into FL's hint bar: letters/digits (any script), space,
// '-', '_', '.'; whitespace runs collapse to one space, trimmed, at most FLIM_NAME_MAX.
// Returns 0 when nothing usable is left (no letter or digit at all).
static int flim_sanitize_name(const wchar_t *in, wchar_t *out, int cap) {
    int o = 0, gap = 0, alnum = 0;
    if (cap > FLIM_NAME_MAX + 1) cap = FLIM_NAME_MAX + 1;
    for (; *in && o < cap - 1; in++) {
        wchar_t c = *in;
        if (c == L' ' || c == L'\t') { gap = o > 0; continue; }
        if (c >= 0xD800 && c <= 0xDFFF) continue;                   // no emoji / surrogates
        if (IsCharAlphaNumericW(c)) alnum = 1;
        else if (c != L'-' && c != L'_' && c != L'.') continue;
        if (gap) { if (o >= cap - 2) break; out[o++] = L' '; gap = 0; }
        out[o++] = c;
    }
    out[o] = 0;
    return alnum;
}

// Password at rest: DPAPI (only this Windows user can decrypt), stored as hex.
static void flimcfg_set_secret(const wchar_t *key, const char *utf8) {
    DATA_BLOB in, out;
    wchar_t *hex;
    DWORD i;
    if (!utf8 || !*utf8) { flimcfg_set(key, NULL); return; }
    in.pbData = (BYTE *)utf8; in.cbData = (DWORD)strlen(utf8);
    if (!CryptProtectData(&in, L"flim", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) return;
    hex = (wchar_t *)malloc(((size_t)out.cbData * 2 + 1) * sizeof(wchar_t));
    for (i = 0; i < out.cbData; i++) swprintf_s(hex + i * 2, 3, L"%02x", out.pbData[i]);
    hex[out.cbData * 2] = 0;
    flimcfg_set(key, hex);
    free(hex);
    LocalFree(out.pbData);
}

static void flimcfg_get_secret(const wchar_t *key, char *out, int cap) {
    wchar_t hex[4096];
    DATA_BLOB in, plain;
    size_t n, i;
    out[0] = 0;
    flimcfg_get(key, hex, 4096);
    n = wcslen(hex) / 2;
    if (!n) return;
    in.pbData = (BYTE *)malloc(n); in.cbData = (DWORD)n;
    for (i = 0; i < n; i++) { unsigned v = 0; swscanf_s(hex + i * 2, L"%2x", &v); in.pbData[i] = (BYTE)v; }
    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
        if ((int)plain.cbData < cap) { memcpy(out, plain.pbData, plain.cbData); out[plain.cbData] = 0; }
        SecureZeroMemory(plain.pbData, plain.cbData);
        LocalFree(plain.pbData);
    }
    free(in.pbData);
}
