#include <windows.h>
#include <winhttp.h>
#include <assert.h>
static int fail_sample_write, fail_sample_flush;
static BOOL WINAPI sample_test_write(HANDLE file, LPCVOID data, DWORD bytes, LPDWORD written, LPOVERLAPPED overlap) {
    if (fail_sample_write) {*written = 0; SetLastError(ERROR_DISK_FULL); return FALSE;}
    return WriteFile(file, data, bytes, written, overlap);
}
static BOOL WINAPI sample_test_flush(HANDLE file) {
    if (fail_sample_flush) {SetLastError(ERROR_DISK_FULL); return FALSE;}
    return FlushFileBuffers(file);
}
#define WriteFile sample_test_write
#define FlushFileBuffers sample_test_flush
#include "../../engine/flim_engine.c"
#undef WriteFile
#undef FlushFileBuffers

static size_t sample_event(unsigned char *out, const wchar_t *path) {
    size_t length = (wcslen(path) + 1) * 2, remain = length, n = 0;
    out[n++] = EV_SAMPLE_PATH;
    do { unsigned char b = (unsigned char)(remain & 127); remain >>= 7; out[n++] = b | (remain ? 128 : 0); } while (remain);
    memcpy(out + n, path, length); return n + length;
}
static void mode(const char *value) {
    assert(blob_http(L"POST", "/test-mode", NULL, 0, value, (DWORD)strlen(value), NULL, NULL, NULL, 0, 0) == 200);
}
int main(int argc, char **argv) {
    unsigned char image[8192] = {0};
    wchar_t source[MAX_PATH], second[MAX_PATH], peer[MAX_PATH], cache[MAX_PATH * 2];
    char *message, hash[65], actual[65], count[16], *copy, *outgoing;
    uint64_t bytes; size_t n = 22; FILE *file;
    assert(argc == 2);
    InitializeCriticalSection(&g_sampleLock); InitializeCriticalSection(&g_netTextLock); InitializeCriticalSection(&g_sendLock);
    assert(parse_host(argv[1], &g_blobUrl)); strcpy_s(g_blobKey, sizeof(g_blobKey), "file-sync-fixture");
    g_blobOn = 1; g_cloudTransport = 1; g_netGen = 1;
    assert(SetEnvironmentVariableA("FLIM_PEER_URL", argv[1]));
    assert(SetEnvironmentVariableA("FLIM_PEER_TOKEN", "1111111111111111111111111111111111111111111111111111111111111111"));
    peer_welcome("{\"file_peer\":\"2222222222222222222222222222222222222222222222222222222222222222\"}"); assert(g_peerReady);
    assert(GetFullPathNameW(L"kick.wav", MAX_PATH, source, NULL));
    assert(GetFullPathNameW(L"same-kick.wav", MAX_PATH, second, NULL));
    assert(GetFullPathNameW(L"peer", MAX_PATH, peer, NULL));
    assert(SetEnvironmentVariableW(L"FLIM_SAMPLE_DIR", peer));
    assert(!_wfopen_s(&file, source, L"wb"));
    assert(fwrite("RIFFflim-file-sync-fixture", 1, 26, file) == 26); assert(!fclose(file));
    assert(CopyFileW(source, second, FALSE));
    memcpy(image, "FLhd", 4); *(uint32_t *)(image + 4) = 6; memcpy(image + 14, "FLdt", 4);
    n += sample_event(image + n, source); n += sample_event(image + n, second); *(uint32_t *)(image + 18) = (uint32_t)(n - 22);
    assert(sample_hash(source, hash, &bytes));
    assert(GetCurrentDirectoryA(sizeof(g_tmpDir), g_tmpDir));
    outgoing = (char *)malloc(n * 2 + 256); assert(outgoing);
    strcpy_s(outgoing, n * 2 + 256, "{\"t\":\"op\",\"op\":{\"kind\":\"chan.add\",\"unit\":\"ch\",\"ch\":7,\"data\":\"");
    b64enc(image, (int)n, outgoing + strlen(outgoing)); strcat_s(outgoing, n * 2 + 256, "\"}}");
    assert(sample_retry_delay(0, 100, 0) == 1000 && sample_retry_delay(9, 100, 0) == 30000);
    assert(sample_retry_delay(0, 100, 60100) == 60000);
    assert(!sample_retryable(403, 1) && sample_retryable(404, 1) && !sample_retryable(404, 0));
    mode("outage-lookup");
    message = samples_prepare_send(outgoing, image, n); free(outgoing);
    assert(message && strstr(message, hash) && !g_compatFault);
    puts("PASS two source names with identical audio upload once and retain both path references");
    puts("PASS a lookup outage recovers automatically after the quick retries are exhausted, without another edit");
    puts("PASS an upload outage recovers automatically before releasing the sample-dependent channel edit");
    g_noLocal = 1;
    mode("retry-download"); samples_resolve(message);
    assert(!g_compatFault && cache_path(hash, source, cache, MAX_PATH * 2));
    assert(hash_file(cache, actual) && !strcmp(actual, hash));
    assert(g_npmap == 2 && !wcscmp(g_pmap[0].to, g_pmap[1].to));
    assert(blob_http(L"GET", "/offer-count", NULL, 0, NULL, 0, NULL, NULL, count, sizeof(count), 0) == 200 && !strcmp(count, "3"));
    puts("PASS background download retries, verifies audio, and maps two paths to one local cached file");
    samples_resolve(message);
    assert(blob_http(L"GET", "/offer-count", NULL, 0, NULL, 0, NULL, NULL, count, sizeof(count), 0) == 200 && !strcmp(count, "3"));
    puts("PASS a repeated shared edit reuses the verified local cache");
    puts("PASS verified received samples are offered to other peers once per unchanged file");
    assert(DeleteFileW(cache));
    {
        int fault;
        for (fault = 0; fault < 2; fault++) {
            fail_sample_write = fault == 0; fail_sample_flush = fault == 1;
            g_sampleRetry = 0; samples_resolve(message);
            assert(g_sampleRetry && !g_compatFault && !file_exists_w(cache) && g_npmap == 0);
            assert(!strcmp(ff_current.reason, "local_cache"));
            fail_sample_write = fail_sample_flush = 0;
        }
        puts("PASS disk-write and flush failures discard incomplete downloads, report storage access, and keep edits pending");
    }
    {
        wchar_t unavailable[MAX_PATH];
        assert(GetFullPathNameW(L"blocked-folder", MAX_PATH, unavailable, NULL));
        assert(!_wfopen_s(&file, unavailable, L"wb")); assert(fwrite("keep", 1, 4, file) == 4); assert(!fclose(file));
        assert(SetEnvironmentVariableW(L"FLIM_SAMPLE_DIR", unavailable));
        g_sampleRetry = 0; samples_resolve(message); assert(g_sampleRetry && !g_compatFault && g_npmap == 0);
        assert(ff_count && !strcmp(ff_current.reason, "local_cache"));
        assert(SetEnvironmentVariableW(L"FLIM_SAMPLE_DIR", L"relative\\invalid"));
        g_sampleRetry = 0; samples_resolve(message); assert(g_sampleRetry && !g_compatFault);
        assert(SetEnvironmentVariableW(L"FLIM_SAMPLE_DIR", peer));
        assert(DeleteFileW(unavailable));
        puts("PASS unusable destinations retain the edit without network requests, stale mappings, fallback folders, or disconnects");
    }
    {
        HANDLE locked;
        assert(!_wfopen_s(&file, cache, L"wb")); assert(fwrite("keep", 1, 4, file) == 4); assert(!fclose(file));
        locked = CreateFileW(cache, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); assert(locked != INVALID_HANDLE_VALUE);
        g_sampleRetry = 0; samples_resolve(message); assert(g_sampleRetry && !g_compatFault && g_npmap == 0);
        assert(!strcmp(ff_current.reason, "local_cache")); assert(CloseHandle(locked));
        {char buf[5] = {0}; assert(!_wfopen_s(&file, cache, L"rb")); assert(fread(buf, 1, 4, file) == 4 && !strcmp(buf, "keep")); assert(!fclose(file));}
        assert(DeleteFileW(cache));
        puts("PASS locked cache replacements report folder access, keep the previous bytes, and wait for automatic retry");
    }
    mode("outage-download"); assert(samples_prepare_receive(message));
    assert(hash_file(cache, actual) && !strcmp(actual, hash));
    { unsigned char *rewritten = (unsigned char *)malloc(n); size_t rn = n; PathList paths = {0};
      assert(rewritten); memcpy(rewritten, image, n); samples_rewrite(&rewritten, &rn);
      assert(flp_walk(rewritten, rn, collect_cb, &paths)); assert(paths.n == 1);
      assert(!wcscmp(paths.paths[0], cache)); pathlist_free(&paths); free(rewritten); }
    puts("PASS a pending download recovers automatically and the preset receives the verified local sample path");
    { int unit, channel, slot; char *preset = NULL; unsigned char *saved; size_t sn; PathList paths = {0};
      assert(parse_unit(message, &unit, &channel, &slot, &preset)); assert(unit == U_CH && channel == 7 && slot == 0);
      saved = read_file(preset, &sn); assert(saved && flp_walk(saved, sn, collect_cb, &paths));
      assert(paths.n == 1 && !wcscmp(paths.paths[0], cache)); pathlist_free(&paths); free(saved);
      assert(DeleteFileA(preset)); free(preset); }
    puts("PASS the real inbound channel parser keeps the channel target and installs the rewritten local preset");
    assert(DeleteFileW(cache));
    mode("recover-verification"); assert(samples_prepare_receive(message));
    assert(hash_file(cache, actual) && !strcmp(actual, hash));
    puts("PASS verification failures retry automatically and release the pending edit only after valid audio arrives");
    assert(DeleteFileW(cache));
    mode("corrupt"); samples_resolve(message); assert(!file_exists_w(cache) && !g_compatFault);
    assert(g_npmap == 0);
    puts("PASS corrupt content never becomes a usable sample, clears stale path mappings, and does not disconnect the room");
    mode("wrong-size");
    copy = _strdup(message); assert(copy);
    { char number[40], *at; sprintf_s(number, sizeof(number), "\"s\":%llu", (unsigned long long)bytes);
      at = copy; while ((at = strstr(at, number)) != NULL) { at[4] = '1'; at += strlen(number); } }
    samples_resolve(copy); assert(!file_exists_w(cache) && !g_compatFault); free(copy);
    puts("PASS sample metadata size is checked as well as its content fingerprint");
    mode("quota"); samples_resolve(message); assert(!g_compatFault && g_sampleBlockedUntil > (LONG64)GetTickCount64());
    assert(sample_http(L"GET", "/blob/blocked", NULL, 0, NULL, 0, NULL, NULL, NULL, 0, 0) == 507);
    puts("PASS a sample allowance blocks further file requests while the room remains connected");
    g_workBound = 1; g_workGen = g_netGen - 1;
    assert(!sample_retry_wait(0)); assert(!samples_prepare_receive(message));
    assert(!samples_prepare_send(message, image, n)); g_workBound = 0;
    puts("PASS reconnect cancels old pending file work instead of applying it in a different session");
    assert(hash_file(source, actual) && !strcmp(actual, hash));
    assert(ff_count >= 2);
    free(message);
    puts("PASS source audio remains untouched and real file status is published");
    return 0;
}
