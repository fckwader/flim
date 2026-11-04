#include <windows.h>
#include <winhttp.h>
#include <assert.h>

static int partial_writes, cancel_read, fail_download_once, check_write_lock;
static BOOL WINAPI transfer_write(HINTERNET request, LPCVOID data, DWORD bytes, LPDWORD written) {
    if (check_write_lock) {
        HANDLE writer = CreateFileW(L"upload.bin", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        assert(writer == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION);
        check_write_lock = 0;
    }
    if (partial_writes && bytes > 1024) bytes = 1024;
    return WinHttpWriteData(request, data, bytes, written);
}
static BOOL WINAPI transfer_read(HINTERNET request, LPVOID data, DWORD bytes, LPDWORD read);
#define WinHttpWriteData transfer_write
#define WinHttpReadData transfer_read
#include "../../engine/flim_engine.c"
#undef WinHttpWriteData
#undef WinHttpReadData

static BOOL WINAPI transfer_read(HINTERNET request, LPVOID data, DWORD bytes, LPDWORD read) {
    BOOL ok;
    if (fail_download_once == 2) { fail_download_once = 0; *read = 0; SetLastError(ERROR_CONNECTION_ABORTED); return FALSE; }
    if (fail_download_once == 1) { if (bytes > 10) bytes = 10; fail_download_once = 2; }
    ok = WinHttpReadData(request, data, bytes, read);
    if (cancel_read && ok && *read) { cancel_read = 0; g_netGen++; }
    return ok;
}

static void lookup_mode(const char *mode) {
    assert(blob_http(L"POST", "/test-mode", NULL, 0, mode, (DWORD)strlen(mode), NULL, NULL, NULL, 0, 0) == 200);
}

static void lookup_recovery(void) {
    SEnt entries[513] = {0};
    unsigned char image[2048] = {0};
    wchar_t full[MAX_PATH];
    size_t length, at, remain;
    char *message;
    int i;
    for (i = 0; i < 513; i++) sprintf_s(entries[i].hex, 65, "%064x", i);
    lookup_mode("retry");
    assert(samples_missing(entries, 1) && entries[0].upload);
    puts("PASS sample lookup retries one temporary service failure");
    lookup_mode("partial");
    assert(!samples_missing(entries, 513));
    for (i = 0; i < 513; i++) assert(!entries[i].upload);
    puts("PASS failed later lookup batch clears every partial upload decision");
    lookup_mode("alien");
    assert(!samples_missing(entries, 1) && !entries[0].upload);
    puts("PASS unrequested sample hashes are rejected");
    lookup_mode("failed");
    assert(GetFullPathNameW(L"upload.bin", MAX_PATH, full, NULL));
    length = (wcslen(full) + 1) * sizeof(wchar_t);
    memcpy(image, "FLhd", 4); *(uint32_t *)(image + 4) = 6;
    memcpy(image + 14, "FLdt", 4); at = 22;
    image[at++] = EV_SAMPLE_PATH; remain = length;
    do { unsigned char b = (unsigned char)(remain & 127); remain >>= 7; image[at++] = b | (remain ? 128 : 0); } while (remain);
    assert(at + length < sizeof(image)); memcpy(image + at, full, length); at += length;
    *(uint32_t *)(image + 18) = (uint32_t)(at - 22);
    message = samples_attach("{\"op\":{\"t\":\"test\"}}", image, at);
    assert(message && strstr(message, "\"samples\":[]") && !g_compatFault);
    free(message);
    puts("PASS failed sample lookup preserves the edit and does not stop sharing");
    message = samples_attach("{ \"op\" : { \"t\" : \"test\" } }", image, at);
    {FlJson root, op, samples; assert(message); root.p = message; root.n = strlen(message);
      assert(fj_get(root, "op", &op) && fj_get(op, "samples", &samples) && fj_is(samples, "[]"));}
    free(message);
    puts("PASS formatted operation objects receive sample metadata without changing their fields");
    message = samples_attach("{\"op\":{}}", image, at);
    {FlJson root, op, samples; assert(message); root.p = message; root.n = strlen(message);
      assert(fj_get(root, "op", &op) && fj_get(op, "samples", &samples));}
    free(message);
    puts("PASS empty operation objects receive valid sample metadata without a trailing comma");
    assert(!samples_attach("{\"op\":{\"samples\":[]}}", image, at) && g_compatFault); g_compatFault = 0; g_compatReady = 1;
    assert(!samples_attach("{\"op\":[]}", image, at) && g_compatFault); g_compatFault = 0; g_compatReady = 1;
    assert(!samples_attach("{\"op\":{}}", image, at - 1) && g_compatFault); g_compatFault = 0; g_compatReady = 1;
    puts("PASS duplicate sample fields, nonobject operations and truncated preset images stop before file transfer");
    lookup_mode("normal");
}

static void peer_transfers(const char *url) {
    char key[65], hash[65], sourceHash[65], count[16], what[96], got[65], welcome[120]; NetUrl endpoint;
    wchar_t source[MAX_PATH]; uint64_t size;
    memset(key, '1', 64); key[64] = 0;
    assert(SetEnvironmentVariableA("FLIM_PEER_URL", "http://remote.invalid:80"));
    assert(SetEnvironmentVariableA("FLIM_PEER_TOKEN", key)); assert(!peer_endpoint(&endpoint, got));
    assert(SetEnvironmentVariableA("FLIM_PEER_URL", url)); assert(peer_endpoint(&endpoint, got));
    memset(key, '2', 64); key[64] = 0;
    sprintf_s(welcome, sizeof(welcome), "{\"file_peer\":\"%s\"}", key);
    peer_welcome(welcome); assert(g_peerReady);
    assert(GetFullPathNameW(L"upload.bin", MAX_PATH, source, NULL));
    assert(sample_hash(source, sourceHash, &size) && size == 65569);
    peer_offer(source, sourceHash, size); peer_offer(source, sourceHash, size);
    assert(blob_http(L"GET", "/offer-count", NULL, 0, NULL, 0, NULL, NULL, count, sizeof(count), 0) == 200 && !strcmp(count, "1"));
    g_netGen++; peer_offer(source, sourceHash, size);
    assert(blob_http(L"GET", "/offer-count", NULL, 0, NULL, 0, NULL, NULL, count, sizeof(count), 0) == 200 && !strcmp(count, "2"));
    puts("PASS unchanged sample registration is deduplicated and renewed in a new native generation");
    assert(sha_hex("flim transfer download", 22, hash));
    sprintf_s(what, sizeof(what), "/blob/%s", hash);
    g_xferDone = 0;
    assert(sample_http(L"GET", what, NULL, 0, NULL, 0, L"peer.bin", got, NULL, 0, 22) == 200);
    assert(!strcmp(hash, got) && g_xferDone == 22);
    InterlockedExchange64(&g_sampleBlockedUntil, GetTickCount64() + 60000);
    assert(sample_http(L"GET", what, NULL, 0, NULL, 0, L"peer-budget.bin", got, NULL, 0, 22) == 200);
    assert(!strcmp(hash, got));
    InterlockedExchange64(&g_sampleBlockedUntil, 0);
    lookup_mode("peer-corrupt"); g_xferDone = 0;
    assert(sample_http(L"GET", what, NULL, 0, NULL, 0, L"peer-fallback.bin", got, NULL, 0, 22) == 200);
    assert(!strcmp(hash, got) && g_xferDone == 22 && !g_sampleVerificationError);
    lookup_mode("peer-missing");
    assert(sample_http(L"GET", what, NULL, 0, NULL, 0, L"peer-missing.bin", got, NULL, 0, 22) == 200);
    assert(file_info(L"peer-missing.bin", &size, NULL) && size == 22);
    lookup_mode("peer-throttle");
    assert(sample_http(L"GET", what, NULL, 0, NULL, 0, L"peer-throttle.bin", got, NULL, 0, 22) == 200);
    assert(!strcmp(hash, got) && !g_compatFault && !g_sampleBlockedUntil);
    puts("PASS optional local peer throttling falls back without pausing the room or R2");
    peer_welcome("{}"); assert(!g_peerReady);
    SetEnvironmentVariableA("FLIM_PEER_URL", NULL); SetEnvironmentVariableA("FLIM_PEER_TOKEN", NULL);
    puts("PASS native peer registration, verified direct bytes, corrupt/missing peer fallback and legacy relay negotiation");
    lookup_mode("normal");
}

int main(int argc, char **argv) {
    SEnt *entries;
    FILE *file;
    char actual[65], expected[65];
    int i;
    uint64_t bytes;
    assert(argc == 2);
    InitializeCriticalSection(&g_sampleLock);
    InitializeCriticalSection(&g_netTextLock);
    InitializeCriticalSection(&g_sendLock);
    assert(parse_host(argv[1], &g_blobUrl));
    strcpy_s(g_blobKey, sizeof(g_blobKey), "local-transfer-fixture");
    g_blobOn = 1; g_cloudTransport = 1; g_netGen = 1;
    assert(sample_sendable(90000000) && !sample_sendable(90000001) && !sample_sendable(0));
    g_cloudTransport = 0;
    assert(sample_sendable(SAMPLE_MAX_BYTES) && !sample_sendable(SAMPLE_MAX_BYTES + 1));
    g_cloudTransport = 1;

    entries = (SEnt *)calloc(1025, sizeof(SEnt));
    assert(entries);
    for (i = 0; i < 1025; i++) sprintf_s(entries[i].hex, 65, "%064x", i);
    assert(samples_missing(entries, 1025));
    for (i = 0; i < 1025; i++) assert(entries[i].upload == (i % 2 == 0));
    free(entries);
    puts("PASS 1025 sample references looked up in bounded batches");

    assert(!fopen_s(&file, "upload.bin", "wb"));
    for (i = 0; i < 65569; i++) fputc(i % 251, file);
    fclose(file);
    partial_writes = check_write_lock = 1;
    assert(blob_http(L"PUT", "/blob/upload", L"upload.bin", 65569, NULL, 0, NULL, NULL, NULL, 0, 0) == 201);
    partial_writes = 0;
    assert(g_xferDone == 65569);
    puts("PASS partial HTTP writes send the complete file");
    assert(!check_write_lock);
    puts("PASS an upload holds its source against concurrent writes while streaming");
    assert(!blob_http(L"PUT", "/blob/upload", L"upload.bin", 65568, NULL, 0, NULL, NULL, NULL, 0, 0));
    puts("PASS a resized upload source is refused before starting the authenticated request");
    lookup_mode("upload-conflict"); g_sampleRetry = 0;
    assert(sample_http(L"PUT", "/blob/upload", L"upload.bin", 65569, NULL, 0, NULL, NULL, NULL, 0, 0) == 409);
    assert(g_sampleRetry && !g_compatFault); g_sampleRetry = 0; lookup_mode("normal");
    puts("PASS an upload content conflict schedules automatic preparation retry without pausing sharing");

    assert(blob_http(L"GET", "/blob/download", NULL, 0, NULL, 0, L"download.bin", actual, NULL, 0, 0) == 200);
    assert(sha_hex("flim transfer download", 22, expected));
    assert(!strcmp(actual, expected));
    assert(file_info(L"download.bin", &bytes, NULL) && bytes == 22);
    puts("PASS streamed download content and checksum");

    assert(blob_http(L"GET", "/blob/download", NULL, 0, NULL, 0, L"oversized.bin", actual, NULL, 0, 21) == 0);
    assert(file_info(L"oversized.bin", &bytes, NULL) && !bytes);
    assert(blob_http(L"GET", "/blob/download", NULL, 0, NULL, 0, L"short.bin", actual, NULL, 0, 23) == 0);
    assert(blob_http(L"GET", "/blob/redirect", NULL, 0, NULL, 0, NULL, NULL, NULL, 0, 0) == 302);
    puts("PASS advertised download length bounds reject oversized/short bodies and authenticated requests never follow redirects");

    g_xferDone = 100; fail_download_once = 1;
    ff_active = 1; ff_current.done = 7; ff_current.bytes = 100;
    assert(sample_http(L"GET", "/blob/download", NULL, 0, NULL, 0, L"retry.bin", actual, NULL, 0, 22) == 200);
    assert(g_xferDone == 122 && file_info(L"retry.bin", &bytes, NULL) && bytes == 22);
    assert(ff_current.done == 29); ff_active = 0;
    puts("PASS a partial download retry replaces failed bytes without inflating progress");
    lookup_recovery();
    peer_transfers(argv[1]);

    g_workBound = 1; g_workGen = g_netGen = 3; cancel_read = 1;
    assert(blob_http(L"GET", "/blob/download", NULL, 0, NULL, 0, L"cancelled.bin", actual, NULL, 0, 0) == 0);
    assert(file_info(L"cancelled.bin", &bytes, NULL) && bytes == 0);
    puts("PASS a stale session stops writing downloaded data");
    return 0;
}
