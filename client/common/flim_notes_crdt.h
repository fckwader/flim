/* Note-merge CRDT for simultaneous piano-roll edits. From cashflowbeatz's flim fork
   (github.com/fckwader/flim pull request #1, commit 764fdc7), used unchanged. */
#ifndef FLIM_NOTES_CRDT_H
#define FLIM_NOTES_CRDT_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FNC_NOTE 24
#define FNC_ENTRY 48
#define FNC_HEADER 32
#define FNC_LIMIT 16384

/* Immutable note identities plus retained observed removals. No tombstone expiry:
   forgetting a removal while an old delta exists could resurrect a deleted note. */
typedef struct { unsigned char id[16], note[FNC_NOTE], dead, reserved[7]; } FncEntry;
typedef char FncEntryWireSize[(sizeof(FncEntry) == FNC_ENTRY) ? 1 : -1];
typedef struct { unsigned char scope[16]; FncEntry *entries; unsigned count; int known; } FncState;
typedef struct { unsigned char note[FNC_NOTE]; unsigned index; } FncRef;
typedef int (*FncId)(unsigned char out[16]);

static int fnc_idcmp(const void *a, const void *b) { return memcmp(((const FncEntry *)a)->id, ((const FncEntry *)b)->id, 16); }
static int fnc_refcmp(const void *a, const void *b) {
    const FncRef *x = (const FncRef *)a, *y = (const FncRef *)b;
    int result = memcmp(x->note, y->note, FNC_NOTE);
    return result ? result : x->index < y->index ? -1 : x->index > y->index;
}
static int fnc_notecmp(const void *a, const void *b) { return memcmp(a, b, FNC_NOTE); }
static void fnc_free(FncState *s) { free(s->entries); memset(s, 0, sizeof(*s)); }

static int fnc_valid(const FncEntry *entries, unsigned count) {
    unsigned i, j;
    if (count > FNC_LIMIT || (count && !entries)) return 0;
    for (i = 0; i < count; i++) {
        unsigned nonzero = 0;
        for (j = 0; j < 16; j++) nonzero |= entries[i].id[j];
        if (!nonzero || entries[i].dead > 1 || (entries[i].note[19] & 128) || (i && fnc_idcmp(entries + i - 1, entries + i) >= 0)) return 0;
        for (j = 0; j < 7; j++) if (entries[i].reserved[j]) return 0;
    }
    return 1;
}

/* Caller supplies a hash of canonical, selection-free baseline records as scope. */
static int fnc_seed(FncState *s, const unsigned char *notes, unsigned count, const unsigned char scope[16]) {
    FncEntry *entries;
    unsigned char saved_scope[16];
    unsigned i, j;
    if (!scope || count > FNC_LIMIT || (count && !notes)) return 0;
    memcpy(saved_scope, scope, 16);
    entries = count ? (FncEntry *)calloc(count, sizeof(*entries)) : NULL;
    if (count && !entries) return 0;
    for (i = 0; i < count; i++) {
        memcpy(entries[i].id, saved_scope, 8);
        for (j = 0; j < 8; j++) entries[i].id[15 - j] = (unsigned char)(((uint64_t)i + 1) >> (8 * j));
        memcpy(entries[i].note, notes + (size_t)i * FNC_NOTE, FNC_NOTE);
    }
    if (!fnc_valid(entries, count)) { free(entries); return 0; }
    fnc_free(s); memcpy(s->scope, saved_scope, 16); s->entries = entries; s->count = count; s->known = 1;
    return 1;
}

/* Join is associative, commutative and idempotent for valid identities. Conflicting
   immutable payloads fail before modifying either input state. */
static int fnc_merge(FncState *s, const unsigned char scope[16], const FncEntry *incoming, unsigned count) {
    FncEntry *merged;
    unsigned a = 0, b = 0, n = 0; int changed = 0;
    if (!s->known || !scope || memcmp(s->scope, scope, 16) || !fnc_valid(incoming, count) || !fnc_valid(s->entries, s->count)) return 0;
    /* Count the union and validate conflicts before allocating or mutating. */
    while (a < s->count || b < count) {
        int order = a == s->count ? 1 : b == count ? -1 : fnc_idcmp(s->entries + a, incoming + b);
        if (++n > FNC_LIMIT) return 0;
        if (order < 0) a++;
        else if (order > 0) { b++; changed = 1; }
        else {
            if (memcmp(s->entries[a].note, incoming[b].note, FNC_NOTE)) return 0;
            if (incoming[b].dead && !s->entries[a].dead) changed = 1;
            a++; b++;
        }
    }
    if (!changed) return 1;
    merged = (FncEntry *)malloc((size_t)n * sizeof(*merged));
    if (!merged) return 0;
    a = b = n = 0;
    while (a < s->count || b < count) {
        int order = a == s->count ? 1 : b == count ? -1 : fnc_idcmp(s->entries + a, incoming + b);
        if (n == FNC_LIMIT) { free(merged); return 0; }
        if (order < 0) merged[n++] = s->entries[a++];
        else if (order > 0) merged[n++] = incoming[b++];
        else {
            if (memcmp(s->entries[a].note, incoming[b].note, FNC_NOTE)) { free(merged); return 0; }
            merged[n] = s->entries[a]; merged[n++].dead |= incoming[b++].dead; a++;
        }
    }
    free(s->entries); s->entries = merged; s->count = n;
    return 1;
}

/* Diff by a sorted multiset, preserving duplicate notes without a quadratic scan.
   A move/velocity change is an observed removal plus a fresh immutable note. */
static int fnc_capture(FncState *s, const unsigned char *notes, unsigned count, FncId new_id, FncEntry **delta, unsigned *changed, unsigned limit) {
    FncRef *before = NULL, *after = NULL;
    FncEntry *next = NULL, *patch = NULL;
    unsigned i, a = 0, b = 0, live = 0, total = s->count, edits = 0, additions = 0;
    *delta = NULL; *changed = 0;
    if (!s->known || limit > FNC_LIMIT || s->count > limit || count > FNC_LIMIT || (count && !notes) || !new_id) return 0;
    for (i = 0; i < s->count; i++) if (!s->entries[i].dead) live++;
    if (!live && !count) return 1;
    before = live ? (FncRef *)malloc((size_t)live * sizeof(*before)) : NULL;
    after = count ? (FncRef *)malloc((size_t)count * sizeof(*after)) : NULL;
    if ((live && !before) || (count && !after)) goto fail;
    live = 0;
    for (i = 0; i < s->count; i++) if (!s->entries[i].dead) { memcpy(before[live].note, s->entries[i].note, FNC_NOTE); before[live++].index = i; }
    for (i = 0; i < count; i++) { memcpy(after[i].note, notes + (size_t)i * FNC_NOTE, FNC_NOTE); after[i].index = i; }
    if (live) qsort(before, live, sizeof(*before), fnc_refcmp);
    if (count) qsort(after, count, sizeof(*after), fnc_refcmp);
    while (a < live || b < count) {
        int order = a == live ? 1 : b == count ? -1 : memcmp(before[a].note, after[b].note, FNC_NOTE);
        if (!order) { a++; b++; }
        else if (order < 0) { a++; edits++; }
        else { b++; additions++; edits++; }
    }
    if (!edits) { free(before); free(after); return 1; }
    if (additions > limit - s->count) goto fail;
    next = (FncEntry *)calloc(s->count + additions, sizeof(*next));
    patch = (FncEntry *)malloc((size_t)edits * sizeof(*patch));
    if (!next || !patch) goto fail;
    if (s->count) memcpy(next, s->entries, (size_t)s->count * sizeof(*next));
    a = b = edits = 0;
    while (a < live || b < count) {
        int order = a == live ? 1 : b == count ? -1 : memcmp(before[a].note, after[b].note, FNC_NOTE);
        if (!order) { a++; b++; }
        else if (order < 0) { next[before[a].index].dead = 1; patch[edits++] = next[before[a++].index]; }
        else {
            if (total == limit || !new_id(next[total].id)) goto fail;
            memcpy(next[total].note, after[b++].note, FNC_NOTE); patch[edits++] = next[total++];
        }
    }
    if (total) qsort(next, total, sizeof(*next), fnc_idcmp);
    if (!fnc_valid(next, total)) goto fail;
    if (edits) qsort(patch, edits, sizeof(*patch), fnc_idcmp);
    free(s->entries); s->entries = next; s->count = total;
    free(before); free(after);
    if (!edits) { free(patch); patch = NULL; }
    *delta = patch; *changed = edits;
    return 1;
fail:
    free(before); free(after); free(next); free(patch); return 0;
}

static unsigned char *fnc_materialize(const FncState *s, unsigned *count) {
    unsigned i, n = 0;
    unsigned char *notes;
    *count = 0;
    for (i = 0; i < s->count; i++) if (!s->entries[i].dead) n++;
    notes = n ? (unsigned char *)malloc((size_t)n * FNC_NOTE) : NULL;
    if (n && !notes) { *count = UINT32_MAX; return NULL; }
    for (i = 0; i < s->count; i++) if (!s->entries[i].dead) memcpy(notes + (size_t)(*count)++ * FNC_NOTE, s->entries[i].note, FNC_NOTE);
    if (n) qsort(notes, n, FNC_NOTE, fnc_notecmp);
    return notes;
}

static unsigned char *fnc_pack(const FncState *s, const FncEntry *entries, unsigned count, unsigned *bytes) {
    unsigned char *wire;
    *bytes = 0;
    if (!s->known || !fnc_valid(entries, count)) return NULL;
    wire = (unsigned char *)calloc(1, FNC_HEADER + count * FNC_ENTRY);
    if (!wire) return NULL;
    *bytes = FNC_HEADER + count * FNC_ENTRY;
    memcpy(wire, "FLIMNC01", 8); memcpy(wire + 8, s->scope, 16);
    wire[24] = (unsigned char)count; wire[25] = (unsigned char)(count >> 8);
    wire[26] = (unsigned char)(count >> 16); wire[27] = (unsigned char)(count >> 24);
    if (count) memcpy(wire + FNC_HEADER, entries, (size_t)count * FNC_ENTRY);
    return wire;
}
static int fnc_unpack(const unsigned char *wire, unsigned bytes, unsigned char scope[16], const FncEntry **entries, unsigned *count) {
    unsigned parsed;
    *entries = NULL; *count = 0; memset(scope, 0, 16);
    if (!wire || bytes < FNC_HEADER || memcmp(wire, "FLIMNC01", 8) || wire[28] || wire[29] || wire[30] || wire[31]) return 0;
    parsed = wire[24] | (unsigned)wire[25] << 8 | (unsigned)wire[26] << 16 | (unsigned)wire[27] << 24;
    if (parsed > FNC_LIMIT || bytes != FNC_HEADER + parsed * FNC_ENTRY || !fnc_valid((const FncEntry *)(wire + FNC_HEADER), parsed)) return 0;
    memcpy(scope, wire + 8, 16); *entries = (const FncEntry *)(wire + FNC_HEADER); *count = parsed;
    return 1;
}
#endif
