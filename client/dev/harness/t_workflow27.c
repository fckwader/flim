#include <assert.h>
#include "../../engine/flim_engine.c"
#undef CH_SELECTED

static unsigned char fixture_image[64], fixture_list[32], objects[4][1024];
static void *fixture_items[4], *fixture_list_ptr, *fixture_move_ptr;
static int operation_mode, calls, move_arg;
static CRITICAL_SECTION fixture_notes;
static char no_plugin(void *obj) {(void)obj; return 0;}
static int resolve_channel(int i, char global, void **out) {(void)global; *out = i >= 0 && i < *(int *)(fixture_list + 16) ? fixture_items[i] : NULL; return *out != NULL;}
static void *add_channel(int a, int b, int c) {
    int n = *(int *)(fixture_list + 16); (void)a; (void)b; (void)c; calls++;
    if (operation_mode == 4) RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
    if (operation_mode != 1) {fixture_items[n] = objects[2]; *(int *)(fixture_list + 16) = n + 1;}
    if (operation_mode == 3) fixture_items[0] = objects[3];
    return operation_mode == 2 ? objects[3] : objects[2];
}
static void delete_channel(unsigned index, char force, uint64_t flags) {
    int i, n = *(int *)(fixture_list + 16); (void)force; (void)flags; calls++;
    if (operation_mode == 2) RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
    if (operation_mode == 1) return;
    if (operation_mode == 3) index = 0;
    for (i = index; i + 1 < n; i++) fixture_items[i] = fixture_items[i + 1];
    *(int *)(fixture_list + 16) = n - 1;
}
static void move_channel(void *obj, uint8_t mode, int arg, uint64_t flags) {
    (void)obj; (void)mode; (void)arg; (void)flags; calls++;
    RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
}
static void reset(void) {
    plug_agreed_reset(1, 1);
    memset(&g_fl, 0, sizeof(g_fl)); memset(g_chU, 0, sizeof(g_chU));
    memset(fixture_image, 0, sizeof(fixture_image)); memset(fixture_list, 0, sizeof(fixture_list));
    memset(objects, 0, sizeof(objects));
    fixture_items[0] = objects[0]; fixture_items[1] = objects[1];
    fixture_list_ptr = fixture_list; fixture_move_ptr = objects[0];
    *(void **)(fixture_list + 8) = fixture_items; *(int *)(fixture_list + 16) = 2;
    *(void **)(fixture_image + 8) = &fixture_list_ptr; *(void **)(fixture_image + 16) = &fixture_list_ptr;
    *(void **)(fixture_image + 24) = &fixture_move_ptr; *(void **)(fixture_image + 32) = &move_arg;
    *(void **)(fixture_image + 40) = &fixture_notes;
    g_flBase = (char *)fixture_image; g_fl.CHANLIST = IMG_BASE + 8; g_fl.CHANFILT = IMG_BASE + 16;
    g_fl.MOVEOBJ = IMG_BASE + 24; g_fl.MOVEARG = IMG_BASE + 32; g_fl.CH_SELECTED = 8;
    g_fl.NOTELOCK = IMG_BASE + 40;
    g_fl.build = L"26.1.7.5654"; g_addChannel = add_channel; g_delChannel = delete_channel;
    g_moveChans = move_channel; g_hasPlugin = no_plugin; g_resolve = resolve_channel;
    g_compatFault = 0; g_compatReady = 1; g_workBound = 0; g_netGen = 1; calls = operation_mode = 0;
    known_from_list();
}
int main(void) {
    QItem task = {0}; int mode; char temp[MAX_PATH], preset[MAX_PATH]; FILE *file;
    setvbuf(stdout, NULL, _IONBF, 0);
    InitializeCriticalSection(&fixture_notes);
    InitializeCriticalSection(&g_qLock); InitializeCriticalSection(&g_sampleLock);
    InitializeCriticalSection(&g_sendLock); InitializeCriticalSection(&g_netTextLock);
    InitializeCriticalSection(&g_slotLock); InitializeCriticalSection(&g_ulockLock);
    InitializeCriticalSection(&g_lifecycleLock); InitializeCriticalSection(&g_heldLock);
    assert(GetTempPathA(MAX_PATH, temp) && GetTempFileNameA(temp, "w27", 0, preset));
    assert(!fopen_s(&file, preset, "wb") && fwrite("preset", 1, 6, file) == 6 && !fclose(file));
    task.unit = U_CH; task.a = 2; task.path = preset; task.mode = 3;
    for (mode = 1; mode <= 4; mode++) {
        reset(); operation_mode = mode; g_chU[2].hash = 123;
        do_addch(&task); assert(g_compatFault && g_chU[2].hash == 123 && g_nChKnown == 2);
    }
    reset(); do_addch(&task); assert(!g_compatFault && g_nChKnown == 3 && g_chU[2].unavailable == 2);
    puts("PASS channel add verifies count, returned object and unchanged prefix; faults preserve bookkeeping; valid append retains newer preset");
    task.a = 1;
    for (mode = 1; mode <= 3; mode++) {
        reset(); operation_mode = mode; g_chU[1].hash = 456;
        do_delch(&task); assert(g_compatFault && g_chU[1].hash == 456 && g_nChKnown == 2);
    }
    reset(); task.a = 5; do_delch(&task); assert(g_compatFault && !calls);
    reset(); task.a = 1; do_delch(&task); assert(g_nChKnown == 1 && fixture_items[0] == objects[0]);
    puts("PASS channel delete verifies mutation and surviving identities before shifting bookkeeping; stale target cannot silently diverge");
    reset(); task.order = NULL; do_order(&task); assert(g_compatFault && !calls);
    {int invalid[] = {MAX_CH + 1}; reset(); task.order = invalid; do_order(&task); assert(g_compatFault && !calls);}
    {int same[] = {2,0,1}; reset(); task.order = same; g_chU[0].hash = 789; do_order(&task); assert(!g_compatFault && !calls && g_chU[0].hash == 789);}
    {int swapped[] = {2,1,0}; reset(); task.order = swapped; objects[0][8] = 1; objects[1][8] = 0;
      do_order(&task); assert(g_compatFault && calls == 1 && objects[0][8] == 1 && objects[1][8] == 0);}
    puts("PASS malformed channel orders and identity moves are handled safely; faulting reorder restores selection and pauses divergent sharing");
    {char hex[65]; uint64_t size = 99; wchar_t wide[MAX_PATH], output[MAX_PATH];
      reset(); assert(MultiByteToWideChar(CP_ACP, 0, preset, -1, wide, MAX_PATH));
      assert(sample_hash(wide, hex, &size) && size == 6); g_workBound = 1; g_workGen = 0;
      assert(!sample_hash(wide, hex, &size) && !hex[0] && !size);
      assert(!find_by_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", output, MAX_PATH) && !output[0]);
      g_workBound = 0; assert(DeleteFileA(preset)); strcpy_s(hex, 65, "previous"); assert(!hash_file(wide, hex) && !hex[0]);}
    puts("PASS stale cached hashes, canceled lookups and failed file hashes clear outputs without reusing an old identity");
    reset(); puts("0.2.27 channel workflow sweep: OK"); return 0;
}
