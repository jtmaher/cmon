/*
 * cmon - Claude Code Token Monitor
 * Real-time ncurses TUI for monitoring Claude Code token usage.
 * Reads from ~/.claude/ data files with inotify for instant updates.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <locale.h>
#include <ncurses.h>
#include "cJSON.h"

/* ── Limits ────────────────────────────────────────────────────── */
#define MAX_MODELS        32
#define MAX_TRACKED_FILES 256
#define MAX_DAILY         512
#define MAX_REQUEST_IDS   32768
#define MAX_MODEL_NAME    128
#define MAX_PATH_LEN      4096
#define INOTIFY_BUF_SIZE  (sizeof(struct inotify_event) + NAME_MAX + 1) * 64
#define TICK_MS           100
#define MAX_DYNAMIC_PRICING 64
#define PRICING_MAX_AGE  (24 * 60 * 60)
#define PRICING_URL      "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"

/* ── Cost per 1M tokens ───────────────────────────────────────── */
typedef struct {
    const char *prefix;
    double input;
    double output;
    double cache_read;
    double cache_write;
} PricingTier;

static const PricingTier PRICING[] = {
    {"claude-opus-4",   15.0,  75.0,  1.875,  18.75},
    {"claude-sonnet-4",  3.0,  15.0,  0.30,    3.75},
    {"claude-haiku-4",   0.80,  4.0,  0.08,    1.00},
    {NULL, 0, 0, 0, 0}
};

typedef struct {
    char model[MAX_MODEL_NAME];
    PricingTier tier;
} DynamicPricingEntry;

static DynamicPricingEntry g_dynamic_pricing[MAX_DYNAMIC_PRICING];
static int g_dynamic_pricing_count = 0;

/* ── Data Structures ──────────────────────────────────────────── */
typedef struct {
    char model[MAX_MODEL_NAME];
    int messages;
    long long input_tokens;
    long long output_tokens;
    long long cache_read;
    long long cache_write;
} ModelTokens;

typedef struct {
    char date[16];
    int message_count;
    int session_count;
    int tool_call_count;
    long long total_tokens;  /* from dailyModelTokens */
    /* Per-model token breakdown (from JSONL parsing) */
    ModelTokens models[MAX_MODELS];
    int model_count;
} DailyStats;

typedef struct {
    char request_id[64];
    long long output_tokens;  /* last seen output count */
} RequestEntry;

typedef struct {
    char path[MAX_PATH_LEN];
    long offset;
    int wd;  /* inotify watch descriptor */
} TrackedFile;

typedef struct {
    /* Today's live token data (from JSONL parsing) */
    ModelTokens today_models[MAX_MODELS];
    int today_model_count;

    /* Historical daily stats (from stats-cache.json) */
    DailyStats daily[MAX_DAILY];
    int daily_count;

    /* All-time model usage (from stats-cache.json) */
    ModelTokens alltime_models[MAX_MODELS];
    int alltime_model_count;
    int total_sessions;
    int total_messages;

    /* Tracked JSONL files */
    TrackedFile tracked[MAX_TRACKED_FILES];
    int tracked_count;

    /* RequestId dedup table */
    RequestEntry requests[MAX_REQUEST_IDS];
    int request_count;

    /* inotify */
    int inotify_fd;
    int stats_wd;

    /* UI state */
    int scroll_offset;
    int max_scroll;
    time_t last_update;
    int running;
    char today_str[16];
    char claude_dir[MAX_PATH_LEN];

    /* inotify fallback */
    int use_polling;
    time_t last_poll;
} CmonState;

/* ── Color pairs ──────────────────────────────────────────────── */
enum {
    CP_HEADER = 1,
    CP_LABEL,
    CP_VALUE,
    CP_COST,
    CP_LIVE,
    CP_MODEL,
    CP_BORDER,
    CP_DIM,
};

/* ── Forward declarations ─────────────────────────────────────── */
static void init_state(CmonState *st);
static void parse_stats_cache(CmonState *st);
static void scan_active_sessions(CmonState *st);
static void scan_historical_sessions(CmonState *st);
static void process_jsonl_line(CmonState *st, const char *line,
                               ModelTokens *models, int *model_count);
static DailyStats *find_or_add_daily(CmonState *st, const char *date);
static void tail_jsonl(CmonState *st, TrackedFile *tf);
static void setup_inotify(CmonState *st);
static void handle_inotify_events(CmonState *st);
static void draw_screen(CmonState *st);
static void format_tokens(long long tokens, char *buf, size_t bufsz);
static double compute_cost(const ModelTokens *mt);
static const PricingTier *find_pricing(const char *model);
static ModelTokens *find_or_add_model(ModelTokens *arr, int *count, int max, const char *model);
static int find_request(CmonState *st, const char *rid);
static void add_tracked_file(CmonState *st, const char *path);
static void poll_files(CmonState *st);
static void load_dynamic_pricing(void);
static int cmp_model_cost_desc(const void *a, const void *b);
static int cmp_daily_date_desc(const void *a, const void *b);

/* ── Utility ──────────────────────────────────────────────────── */

static void get_today_str(char *buf, size_t sz) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(buf, sz, "%Y-%m-%d", tm);
}

static void format_tokens(long long tokens, char *buf, size_t bufsz) {
    if (tokens >= 1000000000LL)
        snprintf(buf, bufsz, "%.1fB", tokens / 1e9);
    else if (tokens >= 1000000LL)
        snprintf(buf, bufsz, "%.1fM", tokens / 1e6);
    else if (tokens >= 1000LL)
        snprintf(buf, bufsz, "%.1fK", tokens / 1e3);
    else
        snprintf(buf, bufsz, "%lld", tokens);
}

/* ── Dynamic Pricing ──────────────────────────────────────────── */

static void ensure_cache_dir(const char *home) {
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/.cache", home);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/.cache/cmon", home);
    mkdir(path, 0755);
}

static int is_cache_fresh(const char *path) {
    struct stat sb;
    if (stat(path, &sb) != 0) return 0;
    return (time(NULL) - sb.st_mtime) < PRICING_MAX_AGE;
}

static char *read_file_to_string(const char *path, long *out_len) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 10 * 1024 * 1024) { fclose(f); return NULL; }
    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    buf[rd] = '\0';
    if (out_len) *out_len = (long)rd;
    return buf;
}

static int write_cache(const char *path, const char *data, long len) {
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    if ((long)written != len) { unlink(tmp); return -1; }
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static char *fetch_url_to_string(const char *url, long *out_len) {
    char cmd[MAX_PATH_LEN];
    snprintf(cmd, sizeof(cmd),
             "curl -sL --max-time 10 --connect-timeout 5 '%s'", url);
    FILE *p = popen(cmd, "r");
    if (!p) return NULL;

    size_t cap = 256 * 1024;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) { pclose(p); return NULL; }

    size_t n;
    while ((n = fread(buf + len, 1, cap - len - 1, p)) > 0) {
        len += n;
        if (len + 1 >= cap) {
            cap *= 2;
            if (cap > 10 * 1024 * 1024) break;
            char *tmp = realloc(buf, cap);
            if (!tmp) break;
            buf = tmp;
        }
    }
    int status = pclose(p);
    if (status != 0 || len == 0) { free(buf); return NULL; }
    buf[len] = '\0';
    if (out_len) *out_len = (long)len;
    return buf;
}

static void parse_litellm_pricing(const char *json_str) {
    cJSON *root = cJSON_Parse(json_str);
    if (!root) return;

    g_dynamic_pricing_count = 0;
    cJSON *entry;
    cJSON_ArrayForEach(entry, root) {
        if (g_dynamic_pricing_count >= MAX_DYNAMIC_PRICING) break;
        const char *key = entry->string;
        if (!key) continue;
        /* Only want top-level claude- models, skip provider-prefixed ones */
        if (strncmp(key, "claude-", 7) != 0) continue;

        if (!cJSON_IsObject(entry)) continue;
        cJSON *inp = cJSON_GetObjectItem(entry, "input_cost_per_token");
        cJSON *out = cJSON_GetObjectItem(entry, "output_cost_per_token");
        if (!cJSON_IsNumber(inp) || !cJSON_IsNumber(out)) continue;

        DynamicPricingEntry *dp = &g_dynamic_pricing[g_dynamic_pricing_count];
        strncpy(dp->model, key, MAX_MODEL_NAME - 1);
        dp->model[MAX_MODEL_NAME - 1] = '\0';
        dp->tier.prefix = dp->model;
        dp->tier.input = inp->valuedouble * 1e6;
        dp->tier.output = out->valuedouble * 1e6;

        cJSON *cr = cJSON_GetObjectItem(entry, "cache_read_input_token_cost");
        dp->tier.cache_read = cJSON_IsNumber(cr) ? cr->valuedouble * 1e6 : dp->tier.input * 0.1;
        cJSON *cw = cJSON_GetObjectItem(entry, "cache_creation_input_token_cost");
        dp->tier.cache_write = cJSON_IsNumber(cw) ? cw->valuedouble * 1e6 : dp->tier.input * 1.25;

        g_dynamic_pricing_count++;
    }
    cJSON_Delete(root);
}

static void load_dynamic_pricing(void) {
    const char *home = getenv("HOME");
    if (!home) return;

    ensure_cache_dir(home);

    char cache_path[MAX_PATH_LEN];
    snprintf(cache_path, sizeof(cache_path), "%s/.cache/cmon/pricing.json", home);

    /* Try fresh cache first */
    if (is_cache_fresh(cache_path)) {
        long len = 0;
        char *data = read_file_to_string(cache_path, &len);
        if (data) {
            parse_litellm_pricing(data);
            free(data);
            if (g_dynamic_pricing_count > 0) return;
        }
    }

    /* Fetch from network */
    long len = 0;
    char *data = fetch_url_to_string(PRICING_URL, &len);
    if (data) {
        parse_litellm_pricing(data);
        if (g_dynamic_pricing_count > 0) {
            write_cache(cache_path, data, len);
        }
        free(data);
        if (g_dynamic_pricing_count > 0) return;
    }

    /* Fall back to stale cache */
    data = read_file_to_string(cache_path, &len);
    if (data) {
        parse_litellm_pricing(data);
        free(data);
    }
    /* If still 0, hardcoded PRICING[] will be used as fallback */
}

static const PricingTier *find_pricing(const char *model) {
    /* 1. Exact match in dynamic pricing */
    for (int i = 0; i < g_dynamic_pricing_count; i++) {
        if (strcmp(model, g_dynamic_pricing[i].model) == 0)
            return &g_dynamic_pricing[i].tier;
    }
    /* 2. Longest-prefix match in dynamic pricing */
    const PricingTier *best = NULL;
    size_t best_len = 0;
    for (int i = 0; i < g_dynamic_pricing_count; i++) {
        size_t plen = strlen(g_dynamic_pricing[i].model);
        if (strncmp(model, g_dynamic_pricing[i].model, plen) == 0 && plen > best_len) {
            best = &g_dynamic_pricing[i].tier;
            best_len = plen;
        }
    }
    if (best) return best;
    /* 3. Longest-prefix match in hardcoded pricing */
    for (int i = 0; PRICING[i].prefix; i++) {
        size_t plen = strlen(PRICING[i].prefix);
        if (strncmp(model, PRICING[i].prefix, plen) == 0 && plen > best_len) {
            best = &PRICING[i];
            best_len = plen;
        }
    }
    return best;
}

static double compute_cost(const ModelTokens *mt) {
    const PricingTier *p = find_pricing(mt->model);
    if (!p) return 0.0;
    return (mt->input_tokens * p->input +
            mt->output_tokens * p->output +
            mt->cache_read * p->cache_read +
            mt->cache_write * p->cache_write) / 1e6;
}

static int cmp_model_cost_desc(const void *a, const void *b) {
    double ca = compute_cost((const ModelTokens *)a);
    double cb = compute_cost((const ModelTokens *)b);
    if (cb > ca) return 1;
    if (cb < ca) return -1;
    return 0;
}

static int cmp_daily_date_desc(const void *a, const void *b) {
    return strcmp(((const DailyStats *)b)->date, ((const DailyStats *)a)->date);
}

static ModelTokens *find_or_add_model(ModelTokens *arr, int *count, int max, const char *model) {
    for (int i = 0; i < *count; i++) {
        if (strcmp(arr[i].model, model) == 0)
            return &arr[i];
    }
    if (*count >= max) return NULL;
    ModelTokens *mt = &arr[*count];
    memset(mt, 0, sizeof(*mt));
    strncpy(mt->model, model, MAX_MODEL_NAME - 1);
    (*count)++;
    return mt;
}

static int find_request(CmonState *st, const char *rid) {
    for (int i = 0; i < st->request_count; i++) {
        if (strcmp(st->requests[i].request_id, rid) == 0)
            return i;
    }
    return -1;
}

/* ── State init ───────────────────────────────────────────────── */

static void init_state(CmonState *st) {
    memset(st, 0, sizeof(*st));
    st->running = 1;
    st->inotify_fd = -1;
    st->stats_wd = -1;
    get_today_str(st->today_str, sizeof(st->today_str));

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Error: HOME not set\n");
        exit(1);
    }
    snprintf(st->claude_dir, sizeof(st->claude_dir), "%s/.claude", home);

    struct stat sb;
    if (stat(st->claude_dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
        fprintf(stderr, "Error: %s does not exist. Is Claude Code installed?\n", st->claude_dir);
        exit(1);
    }
}

/* ── Parse stats-cache.json ───────────────────────────────────── */

static void parse_stats_cache(CmonState *st) {
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/stats-cache.json", st->claude_dir);

    FILE *f = fopen(path, "r");
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 10 * 1024 * 1024) { fclose(f); return; }

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return; }
    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    buf[rd] = '\0';

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) return;

    /* Compute cutoff date string (30 days ago) for filtering */
    char cutoff_date[16];
    {
        time_t cutoff = time(NULL) - 30 * 24 * 60 * 60;
        struct tm *ct = localtime(&cutoff);
        strftime(cutoff_date, sizeof(cutoff_date), "%Y-%m-%d", ct);
    }

    /* dailyActivity */
    st->daily_count = 0;
    cJSON *da = cJSON_GetObjectItem(root, "dailyActivity");
    if (cJSON_IsArray(da)) {
        cJSON *item;
        cJSON_ArrayForEach(item, da) {
            if (st->daily_count >= MAX_DAILY) break;
            cJSON *d = cJSON_GetObjectItem(item, "date");
            if (!cJSON_IsString(d)) continue;
            if (strcmp(d->valuestring, cutoff_date) < 0) continue;
            DailyStats *ds = &st->daily[st->daily_count];
            memset(ds, 0, sizeof(*ds));
            strncpy(ds->date, d->valuestring, sizeof(ds->date) - 1);
            cJSON *mc = cJSON_GetObjectItem(item, "messageCount");
            if (cJSON_IsNumber(mc)) ds->message_count = (int)mc->valuedouble;
            cJSON *sc = cJSON_GetObjectItem(item, "sessionCount");
            if (cJSON_IsNumber(sc)) ds->session_count = (int)sc->valuedouble;
            cJSON *tc = cJSON_GetObjectItem(item, "toolCallCount");
            if (cJSON_IsNumber(tc)) ds->tool_call_count = (int)tc->valuedouble;
            st->daily_count++;
        }
    }

    /* dailyModelTokens — merge token counts into daily[] */
    cJSON *dmt = cJSON_GetObjectItem(root, "dailyModelTokens");
    if (cJSON_IsArray(dmt)) {
        cJSON *item;
        cJSON_ArrayForEach(item, dmt) {
            cJSON *d = cJSON_GetObjectItem(item, "date");
            if (!cJSON_IsString(d)) continue;
            cJSON *tbm = cJSON_GetObjectItem(item, "tokensByModel");
            if (!cJSON_IsObject(tbm)) continue;
            long long total = 0;
            cJSON *val;
            cJSON_ArrayForEach(val, tbm) {
                if (cJSON_IsNumber(val))
                    total += (long long)val->valuedouble;
            }
            /* find matching daily entry */
            for (int i = 0; i < st->daily_count; i++) {
                if (strcmp(st->daily[i].date, d->valuestring) == 0) {
                    st->daily[i].total_tokens = total;
                    break;
                }
            }
        }
    }

    /* modelUsage */
    st->alltime_model_count = 0;
    cJSON *mu = cJSON_GetObjectItem(root, "modelUsage");
    if (cJSON_IsObject(mu)) {
        cJSON *entry;
        cJSON_ArrayForEach(entry, mu) {
            ModelTokens *mt = find_or_add_model(st->alltime_models,
                &st->alltime_model_count, MAX_MODELS, entry->string);
            if (!mt) continue;
            cJSON *v;
            v = cJSON_GetObjectItem(entry, "inputTokens");
            if (cJSON_IsNumber(v)) mt->input_tokens = (long long)v->valuedouble;
            v = cJSON_GetObjectItem(entry, "outputTokens");
            if (cJSON_IsNumber(v)) mt->output_tokens = (long long)v->valuedouble;
            v = cJSON_GetObjectItem(entry, "cacheReadInputTokens");
            if (cJSON_IsNumber(v)) mt->cache_read = (long long)v->valuedouble;
            v = cJSON_GetObjectItem(entry, "cacheCreationInputTokens");
            if (cJSON_IsNumber(v)) mt->cache_write = (long long)v->valuedouble;
        }
    }

    cJSON *ts = cJSON_GetObjectItem(root, "totalSessions");
    if (cJSON_IsNumber(ts)) st->total_sessions = (int)ts->valuedouble;
    cJSON *tm = cJSON_GetObjectItem(root, "totalMessages");
    if (cJSON_IsNumber(tm)) st->total_messages = (int)tm->valuedouble;

    cJSON_Delete(root);
}

/* ── JSONL Processing ─────────────────────────────────────────── */

static void process_jsonl_line(CmonState *st, const char *line,
                               ModelTokens *models, int *model_count) {
    /* Quick reject: only parse lines containing "type":"assistant" */
    if (!strstr(line, "\"type\":\"assistant\""))
        return;

    cJSON *root = cJSON_Parse(line);
    if (!root) return;

    cJSON *type = cJSON_GetObjectItem(root, "type");
    if (!cJSON_IsString(type) || strcmp(type->valuestring, "assistant") != 0) {
        cJSON_Delete(root);
        return;
    }

    cJSON *msg = cJSON_GetObjectItem(root, "message");
    if (!cJSON_IsObject(msg)) { cJSON_Delete(root); return; }

    cJSON *usage = cJSON_GetObjectItem(msg, "usage");
    if (!cJSON_IsObject(usage)) { cJSON_Delete(root); return; }

    cJSON *model_j = cJSON_GetObjectItem(msg, "model");
    if (!cJSON_IsString(model_j)) { cJSON_Delete(root); return; }
    const char *model = model_j->valuestring;

    long long in_tok = 0, out_tok = 0, cache_r = 0, cache_w = 0;
    cJSON *v;
    v = cJSON_GetObjectItem(usage, "input_tokens");
    if (cJSON_IsNumber(v)) in_tok = (long long)v->valuedouble;
    v = cJSON_GetObjectItem(usage, "output_tokens");
    if (cJSON_IsNumber(v)) out_tok = (long long)v->valuedouble;
    v = cJSON_GetObjectItem(usage, "cache_read_input_tokens");
    if (cJSON_IsNumber(v)) cache_r = (long long)v->valuedouble;
    v = cJSON_GetObjectItem(usage, "cache_creation_input_tokens");
    if (cJSON_IsNumber(v)) cache_w = (long long)v->valuedouble;

    /* Dedup by requestId: for same requestId, input/cache tokens are same,
       output_tokens grows. We keep the max output and only count input/cache once. */
    cJSON *rid_j = cJSON_GetObjectItem(root, "requestId");
    const char *rid = cJSON_IsString(rid_j) ? rid_j->valuestring : "";

    ModelTokens *mt = find_or_add_model(models, model_count, MAX_MODELS, model);
    if (!mt) { cJSON_Delete(root); return; }

    if (rid[0] != '\0') {
        int idx = find_request(st, rid);
        if (idx >= 0) {
            /* Seen this requestId before — only add output delta */
            long long prev_out = st->requests[idx].output_tokens;
            if (out_tok > prev_out) {
                mt->output_tokens += (out_tok - prev_out);
                st->requests[idx].output_tokens = out_tok;
            }
            /* input/cache already counted, skip */
        } else {
            /* New requestId — count everything */
            mt->messages++;
            mt->input_tokens += in_tok;
            mt->output_tokens += out_tok;
            mt->cache_read += cache_r;
            mt->cache_write += cache_w;
            if (st->request_count < MAX_REQUEST_IDS) {
                RequestEntry *re = &st->requests[st->request_count++];
                strncpy(re->request_id, rid, sizeof(re->request_id) - 1);
                re->output_tokens = out_tok;
            }
        }
    } else {
        /* No requestId — just add directly */
        mt->messages++;
        mt->input_tokens += in_tok;
        mt->output_tokens += out_tok;
        mt->cache_read += cache_r;
        mt->cache_write += cache_w;
    }

    st->last_update = time(NULL);
    cJSON_Delete(root);
}

static void tail_jsonl(CmonState *st, TrackedFile *tf) {
    FILE *f = fopen(tf->path, "r");
    if (!f) return;

    /* Check if file was truncated/rotated */
    fseek(f, 0, SEEK_END);
    long filesz = ftell(f);
    if (filesz < tf->offset) {
        tf->offset = 0; /* reset on truncation */
    }

    if (filesz <= tf->offset) {
        fclose(f);
        return;
    }

    fseek(f, tf->offset, SEEK_SET);

    char *line = NULL;
    size_t linesz = 0;
    while (getline(&line, &linesz, f) > 0) {
        /* Only process complete lines */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            process_jsonl_line(st, line,
                               st->today_models, &st->today_model_count);
        }
    }

    tf->offset = ftell(f);
    free(line);
    fclose(f);
}

/* ── File scanning ────────────────────────────────────────────── */

static void add_tracked_file(CmonState *st, const char *path) {
    /* Check if already tracked */
    for (int i = 0; i < st->tracked_count; i++) {
        if (strcmp(st->tracked[i].path, path) == 0)
            return;
    }
    if (st->tracked_count >= MAX_TRACKED_FILES) return;

    TrackedFile *tf = &st->tracked[st->tracked_count++];
    snprintf(tf->path, MAX_PATH_LEN, "%s", path);
    tf->offset = 0;
    tf->wd = -1;

    /* Add inotify watch */
    if (st->inotify_fd >= 0) {
        tf->wd = inotify_add_watch(st->inotify_fd, path, IN_MODIFY);
    }
}

static int is_modified_today(const char *path, const char *today) {
    struct stat sb;
    if (stat(path, &sb) != 0) return 0;
    struct tm *tm = localtime(&sb.st_mtime);
    char date[16];
    strftime(date, sizeof(date), "%Y-%m-%d", tm);
    return strcmp(date, today) == 0;
}

static void scan_dir_for_jsonl(CmonState *st, const char *dirpath) {
    DIR *d = opendir(dirpath);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char fullpath[MAX_PATH_LEN];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, ent->d_name);

        struct stat sb;
        if (stat(fullpath, &sb) != 0) continue;

        if (S_ISDIR(sb.st_mode)) {
            /* Recurse into subdirectories (for subagents/) */
            scan_dir_for_jsonl(st, fullpath);
        } else if (S_ISREG(sb.st_mode)) {
            size_t nlen = strlen(ent->d_name);
            if (nlen > 6 && strcmp(ent->d_name + nlen - 6, ".jsonl") == 0) {
                if (is_modified_today(fullpath, st->today_str)) {
                    add_tracked_file(st, fullpath);
                }
            }
        }
    }
    closedir(d);
}

static void scan_active_sessions(CmonState *st) {
    /* Reset today data */
    st->today_model_count = 0;
    st->request_count = 0;

    /* Reset tracked file offsets so we re-parse */
    for (int i = 0; i < st->tracked_count; i++) {
        st->tracked[i].offset = 0;
    }
    st->tracked_count = 0;

    char projects_dir[MAX_PATH_LEN];
    snprintf(projects_dir, sizeof(projects_dir), "%s/projects", st->claude_dir);

    DIR *d = opendir(projects_dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char projpath[MAX_PATH_LEN];
        snprintf(projpath, sizeof(projpath), "%s/%s", projects_dir, ent->d_name);
        struct stat sb;
        if (stat(projpath, &sb) == 0 && S_ISDIR(sb.st_mode)) {
            scan_dir_for_jsonl(st, projpath);
        }
    }
    closedir(d);

    /* Parse all tracked files fully */
    for (int i = 0; i < st->tracked_count; i++) {
        tail_jsonl(st, &st->tracked[i]);
    }

    st->last_update = time(NULL);
}

static DailyStats *find_or_add_daily(CmonState *st, const char *date) {
    for (int i = 0; i < st->daily_count; i++) {
        if (strcmp(st->daily[i].date, date) == 0)
            return &st->daily[i];
    }
    if (st->daily_count >= MAX_DAILY) return NULL;
    DailyStats *ds = &st->daily[st->daily_count++];
    memset(ds, 0, sizeof(*ds));
    snprintf(ds->date, sizeof(ds->date), "%s", date);
    return ds;
}

static void parse_jsonl_file(CmonState *st, const char *path,
                             ModelTokens *models, int *model_count) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char *line = NULL;
    size_t linesz = 0;
    while (getline(&line, &linesz, f) > 0) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            process_jsonl_line(st, line, models, model_count);
        }
    }
    free(line);
    fclose(f);
}

static void scan_historical_sessions(CmonState *st) {
    st->request_count = 0;
    /* Reset all daily model data */
    for (int i = 0; i < st->daily_count; i++) {
        st->daily[i].model_count = 0;
        memset(st->daily[i].models, 0, sizeof(st->daily[i].models));
    }

    time_t cutoff = time(NULL) - 30 * 24 * 60 * 60; /* 30 days ago */

    char projects_dir[MAX_PATH_LEN];
    snprintf(projects_dir, sizeof(projects_dir), "%s/projects", st->claude_dir);

    DIR *pd = opendir(projects_dir);
    if (!pd) return;

    struct dirent *pent;
    while ((pent = readdir(pd)) != NULL) {
        if (pent->d_name[0] == '.') continue;
        char projpath[MAX_PATH_LEN];
        snprintf(projpath, sizeof(projpath), "%s/%s", projects_dir, pent->d_name);
        struct stat psb;
        if (stat(projpath, &psb) != 0 || !S_ISDIR(psb.st_mode)) continue;

        /* Recursively find all .jsonl files in this project */
        DIR *stack[16];
        char dirpaths[16][MAX_PATH_LEN];
        int depth = 0;
        snprintf(dirpaths[0], MAX_PATH_LEN, "%s", projpath);
        stack[0] = opendir(projpath);
        if (!stack[0]) continue;

        while (depth >= 0) {
            struct dirent *ent = readdir(stack[depth]);
            if (!ent) {
                closedir(stack[depth]);
                depth--;
                continue;
            }
            if (ent->d_name[0] == '.') continue;

            char fullpath[MAX_PATH_LEN];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpaths[depth], ent->d_name);

            struct stat sb;
            if (stat(fullpath, &sb) != 0) continue;

            if (S_ISDIR(sb.st_mode) && depth < 15) {
                depth++;
                snprintf(dirpaths[depth], MAX_PATH_LEN, "%s", fullpath);
                stack[depth] = opendir(fullpath);
                if (!stack[depth]) { depth--; continue; }
            } else if (S_ISREG(sb.st_mode)) {
                size_t nlen = strlen(ent->d_name);
                if (nlen > 6 && strcmp(ent->d_name + nlen - 6, ".jsonl") == 0) {
                    /* Skip files older than 30 days */
                    if (sb.st_mtime < cutoff) continue;
                    /* Skip today's files — handled by scan_active_sessions */
                    if (is_modified_today(fullpath, st->today_str)) continue;

                    /* Determine date from file mtime */
                    char date[16];
                    struct tm *tm = localtime(&sb.st_mtime);
                    strftime(date, sizeof(date), "%Y-%m-%d", tm);

                    DailyStats *ds = find_or_add_daily(st, date);
                    if (!ds) continue;

                    parse_jsonl_file(st, fullpath, ds->models, &ds->model_count);
                }
            }
        }
    }
    closedir(pd);
}

/* ── inotify ──────────────────────────────────────────────────── */

static void setup_inotify(CmonState *st) {
    st->inotify_fd = inotify_init1(IN_NONBLOCK);
    if (st->inotify_fd < 0) {
        st->use_polling = 1;
        return;
    }

    /* Watch stats-cache.json */
    char stats_path[MAX_PATH_LEN];
    snprintf(stats_path, sizeof(stats_path), "%s/stats-cache.json", st->claude_dir);
    st->stats_wd = inotify_add_watch(st->inotify_fd, stats_path, IN_MODIFY | IN_CLOSE_WRITE);

    /* Watch projects directory for new files */
    char projects_dir[MAX_PATH_LEN];
    snprintf(projects_dir, sizeof(projects_dir), "%s/projects", st->claude_dir);
    inotify_add_watch(st->inotify_fd, projects_dir, IN_CREATE | IN_MODIFY);

    /* Watch each tracked file */
    for (int i = 0; i < st->tracked_count; i++) {
        if (st->tracked[i].wd < 0) {
            st->tracked[i].wd = inotify_add_watch(st->inotify_fd,
                st->tracked[i].path, IN_MODIFY);
        }
    }
}

static void handle_inotify_events(CmonState *st) {
    if (st->use_polling) {
        poll_files(st);
        return;
    }

    char buf[INOTIFY_BUF_SIZE];
    int need_stats_reload = 0;
    int need_rescan = 0;

    for (;;) {
        ssize_t len = read(st->inotify_fd, buf, sizeof(buf));
        if (len <= 0) break;

        char *ptr = buf;
        while (ptr < buf + len) {
            struct inotify_event *ev = (struct inotify_event *)ptr;

            if (ev->wd == st->stats_wd) {
                need_stats_reload = 1;
            } else {
                /* Check if it's a tracked file */
                int found = 0;
                for (int i = 0; i < st->tracked_count; i++) {
                    if (st->tracked[i].wd == ev->wd) {
                        tail_jsonl(st, &st->tracked[i]);
                        found = 1;
                        break;
                    }
                }
                if (!found && (ev->mask & IN_CREATE)) {
                    need_rescan = 1;
                }
            }

            ptr += sizeof(struct inotify_event) + ev->len;
        }
    }

    if (need_stats_reload) {
        parse_stats_cache(st);
        st->last_update = time(NULL);
    }

    if (need_rescan) {
        /* New file in projects dir — rescan for today's files */
        char projects_dir[MAX_PATH_LEN];
        snprintf(projects_dir, sizeof(projects_dir), "%s/projects", st->claude_dir);
        DIR *d = opendir(projects_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char projpath[MAX_PATH_LEN];
                snprintf(projpath, sizeof(projpath), "%s/%s", projects_dir, ent->d_name);
                struct stat sb;
                if (stat(projpath, &sb) == 0 && S_ISDIR(sb.st_mode)) {
                    scan_dir_for_jsonl(st, projpath);
                }
            }
            closedir(d);
        }
    }
}

static void poll_files(CmonState *st) {
    time_t now = time(NULL);
    if (now - st->last_poll < 2) return;
    st->last_poll = now;

    /* Check stats-cache.json */
    char stats_path[MAX_PATH_LEN];
    snprintf(stats_path, sizeof(stats_path), "%s/stats-cache.json", st->claude_dir);
    struct stat sb;
    if (stat(stats_path, &sb) == 0) {
        static time_t last_stats_mtime = 0;
        if (sb.st_mtime != last_stats_mtime) {
            last_stats_mtime = sb.st_mtime;
            parse_stats_cache(st);
            st->last_update = time(NULL);
        }
    }

    /* Check tracked files */
    for (int i = 0; i < st->tracked_count; i++) {
        tail_jsonl(st, &st->tracked[i]);
    }
}

/* ── ncurses Drawing ──────────────────────────────────────────── */

static void draw_hline(int row, int cols) {
    attron(COLOR_PAIR(CP_BORDER));
    mvhline(row, 0, ACS_HLINE, cols);
    attroff(COLOR_PAIR(CP_BORDER));
}

static void draw_header(int cols) {
    attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvhline(0, 0, ' ', cols);
    mvprintw(0, 2, "CMON - Claude Monitor");
    mvprintw(0, cols - 16, "[q]uit [r]escan");
    attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);
}

static int draw_today(CmonState *st, int row, int cols) {
    draw_hline(row, cols);
    row++;

    /* Section title with live indicator */
    attron(COLOR_PAIR(CP_LABEL) | A_BOLD);
    mvprintw(row, 2, "TODAY (%s)", st->today_str);
    attroff(COLOR_PAIR(CP_LABEL) | A_BOLD);

    time_t now = time(NULL);
    if (now - st->last_update < 10) {
        attron(COLOR_PAIR(CP_LIVE) | A_BOLD);
        mvprintw(row, cols - 8, "● Live");
        attroff(COLOR_PAIR(CP_LIVE) | A_BOLD);
    }
    row++;

    if (st->today_model_count == 0) {
        attron(COLOR_PAIR(CP_DIM));
        mvprintw(row, 4, "No token data for today yet");
        attroff(COLOR_PAIR(CP_DIM));
        return row + 1;
    }

    /* Column header */
    attron(COLOR_PAIR(CP_DIM));
    mvprintw(row, 4, "%-24s %5s %9s %9s %9s %9s %10s", "Model", "Msgs", "Input", "Output", "Cache.R", "Cache.W", "Cost");
    attroff(COLOR_PAIR(CP_DIM));
    row++;

    qsort(st->today_models, st->today_model_count, sizeof(ModelTokens), cmp_model_cost_desc);

    long long tot_in = 0, tot_out = 0, tot_cr = 0, tot_cw = 0;
    int tot_msgs = 0;
    double tot_cost = 0;

    for (int i = 0; i < st->today_model_count; i++) {
        ModelTokens *mt = &st->today_models[i];
        if (mt->input_tokens == 0 && mt->output_tokens == 0 &&
            mt->cache_read == 0 && mt->cache_write == 0) continue;
        char in_s[16], out_s[16], cr_s[16], cw_s[16];
        format_tokens(mt->input_tokens, in_s, sizeof(in_s));
        format_tokens(mt->output_tokens, out_s, sizeof(out_s));
        format_tokens(mt->cache_read, cr_s, sizeof(cr_s));
        format_tokens(mt->cache_write, cw_s, sizeof(cw_s));
        double cost = compute_cost(mt);

        attron(COLOR_PAIR(CP_MODEL));
        mvprintw(row, 4, "%-24s", mt->model);
        attroff(COLOR_PAIR(CP_MODEL));
        attron(COLOR_PAIR(CP_VALUE));
        mvprintw(row, 28, " %5d", mt->messages);
        attroff(COLOR_PAIR(CP_VALUE));
        attron(COLOR_PAIR(CP_VALUE) | A_BOLD);
        mvprintw(row, 34, " %9s %9s %9s %9s", in_s, out_s, cr_s, cw_s);
        attroff(COLOR_PAIR(CP_VALUE) | A_BOLD);
        attron(COLOR_PAIR(CP_COST) | A_BOLD);
        mvprintw(row, 74, " $%7.2f", cost);
        attroff(COLOR_PAIR(CP_COST) | A_BOLD);
        row++;

        tot_in += mt->input_tokens;
        tot_out += mt->output_tokens;
        tot_cr += mt->cache_read;
        tot_cw += mt->cache_write;
        tot_msgs += mt->messages;
        tot_cost += cost;
    }

    if (st->today_model_count > 1) {
        char in_s[16], out_s[16], cr_s[16], cw_s[16];
        format_tokens(tot_in, in_s, sizeof(in_s));
        format_tokens(tot_out, out_s, sizeof(out_s));
        format_tokens(tot_cr, cr_s, sizeof(cr_s));
        format_tokens(tot_cw, cw_s, sizeof(cw_s));

        attron(COLOR_PAIR(CP_LABEL) | A_BOLD);
        mvprintw(row, 4, "%-24s", "TOTAL");
        attroff(COLOR_PAIR(CP_LABEL) | A_BOLD);
        attron(COLOR_PAIR(CP_VALUE) | A_BOLD);
        mvprintw(row, 28, " %5d", tot_msgs);
        mvprintw(row, 34, " %9s %9s %9s %9s", in_s, out_s, cr_s, cw_s);
        attroff(COLOR_PAIR(CP_VALUE) | A_BOLD);
        attron(COLOR_PAIR(CP_COST) | A_BOLD);
        mvprintw(row, 74, " $%7.2f", tot_cost);
        attroff(COLOR_PAIR(CP_COST) | A_BOLD);
        row++;
    }

    return row;
}

static int draw_daily_history(CmonState *st, int row, int rows, int cols) {
    draw_hline(row, cols);
    row++;

    attron(COLOR_PAIR(CP_LABEL) | A_BOLD);
    mvprintw(row, 2, "DAILY HISTORY");
    attroff(COLOR_PAIR(CP_LABEL) | A_BOLD);
    attron(COLOR_PAIR(CP_DIM));
    mvprintw(row, cols - 16, "[j/k scroll]");
    attroff(COLOR_PAIR(CP_DIM));
    row++;

    if (st->daily_count == 0) {
        attron(COLOR_PAIR(CP_DIM));
        mvprintw(row, 4, "No daily history data");
        attroff(COLOR_PAIR(CP_DIM));
        return row + 1;
    }

    /* Column header — same grid as TODAY / ALL TIME */
    attron(COLOR_PAIR(CP_DIM));
    mvprintw(row, 4, "%-24s %5s %9s %9s %9s %9s %10s", "Date", "Msgs", "Input", "Output", "Cache.R", "Cache.W", "Cost");
    attroff(COLOR_PAIR(CP_DIM));
    row++;

    /* Show daily stats in reverse chronological order */
    int avail_rows = rows - row - 8; /* leave room for alltime + status */
    if (avail_rows < 3) avail_rows = 3;
    if (avail_rows > 10) avail_rows = 10;

    st->max_scroll = st->daily_count - avail_rows;
    if (st->max_scroll < 0) st->max_scroll = 0;
    if (st->scroll_offset > st->max_scroll)
        st->scroll_offset = st->max_scroll;

    for (int j = 0; j < avail_rows && row < rows - 8; j++) {
        int idx = j + st->scroll_offset;
        if (idx >= st->daily_count) break;
        DailyStats *ds = &st->daily[idx];
        int is_today = (strcmp(ds->date, st->today_str) == 0);

        /* For today, use live data; for historical, use JSONL-derived daily data */
        ModelTokens *src = is_today ? st->today_models : ds->models;
        int src_count = is_today ? st->today_model_count : ds->model_count;

        long long tot_in = 0, tot_out = 0, tot_cr = 0, tot_cw = 0;
        int tot_msgs = 0;
        double cost = 0;
        for (int k = 0; k < src_count; k++) {
            tot_in  += src[k].input_tokens;
            tot_out += src[k].output_tokens;
            tot_cr  += src[k].cache_read;
            tot_cw  += src[k].cache_write;
            tot_msgs += src[k].messages;
            cost    += compute_cost(&src[k]);
        }

        char in_s[16], out_s[16], cr_s[16], cw_s[16];
        format_tokens(tot_in, in_s, sizeof(in_s));
        format_tokens(tot_out, out_s, sizeof(out_s));
        format_tokens(tot_cr, cr_s, sizeof(cr_s));
        format_tokens(tot_cw, cw_s, sizeof(cw_s));

        /* Date column */
        if (is_today) attron(COLOR_PAIR(CP_VALUE) | A_BOLD);
        mvprintw(row, 4, "%-24s", ds->date);
        if (is_today) attroff(COLOR_PAIR(CP_VALUE) | A_BOLD);

        /* Msgs column */
        attron(COLOR_PAIR(CP_VALUE) | (is_today ? A_BOLD : 0));
        mvprintw(row, 28, " %5d", tot_msgs);
        attroff(COLOR_PAIR(CP_VALUE) | (is_today ? A_BOLD : 0));

        /* Token columns */
        attron(COLOR_PAIR(CP_VALUE) | (is_today ? A_BOLD : 0));
        mvprintw(row, 34, " %9s %9s %9s %9s", in_s, out_s, cr_s, cw_s);
        attroff(COLOR_PAIR(CP_VALUE) | (is_today ? A_BOLD : 0));

        /* Cost column */
        if (src_count > 0) {
            attron(COLOR_PAIR(CP_COST) | (is_today ? A_BOLD : 0));
            mvprintw(row, 74, " $%7.2f", cost);
            attroff(COLOR_PAIR(CP_COST) | (is_today ? A_BOLD : 0));
        }

        row++;
    }

    return row;
}

static int draw_alltime(CmonState *st, int row, int cols) {
    draw_hline(row, cols);
    row++;

    attron(COLOR_PAIR(CP_LABEL) | A_BOLD);
    mvprintw(row, 2, "ALL TIME — %d sessions, %d messages",
             st->total_sessions, st->total_messages);
    attroff(COLOR_PAIR(CP_LABEL) | A_BOLD);
    row++;

    /* Build aggregated per-model totals from all daily JSONL data + today */
    ModelTokens agg[MAX_MODELS];
    int agg_count = 0;
    memset(agg, 0, sizeof(agg));

    /* Sum all historical daily entries */
    for (int d = 0; d < st->daily_count; d++) {
        DailyStats *ds = &st->daily[d];
        int is_today = (strcmp(ds->date, st->today_str) == 0);
        if (is_today) continue; /* today added separately from live data */
        for (int m = 0; m < ds->model_count; m++) {
            ModelTokens *src = &ds->models[m];
            ModelTokens *dst = find_or_add_model(agg, &agg_count, MAX_MODELS, src->model);
            if (!dst) continue;
            dst->messages += src->messages;
            dst->input_tokens += src->input_tokens;
            dst->output_tokens += src->output_tokens;
            dst->cache_read += src->cache_read;
            dst->cache_write += src->cache_write;
        }
    }

    /* Add today's live data */
    for (int i = 0; i < st->today_model_count; i++) {
        ModelTokens *src = &st->today_models[i];
        ModelTokens *dst = find_or_add_model(agg, &agg_count, MAX_MODELS, src->model);
        if (!dst) continue;
        dst->messages += src->messages;
        dst->input_tokens += src->input_tokens;
        dst->output_tokens += src->output_tokens;
        dst->cache_read += src->cache_read;
        dst->cache_write += src->cache_write;
    }

    /* Column header (same as TODAY) */
    attron(COLOR_PAIR(CP_DIM));
    mvprintw(row, 4, "%-24s %5s %9s %9s %9s %9s %10s", "Model", "Msgs", "Input", "Output", "Cache.R", "Cache.W", "Cost");
    attroff(COLOR_PAIR(CP_DIM));
    row++;

    qsort(agg, agg_count, sizeof(ModelTokens), cmp_model_cost_desc);

    long long tot_in = 0, tot_out = 0, tot_cr = 0, tot_cw = 0;
    int tot_msgs = 0;
    double total_cost = 0;
    for (int i = 0; i < agg_count; i++) {
        ModelTokens *mt = &agg[i];
        if (mt->input_tokens == 0 && mt->output_tokens == 0 &&
            mt->cache_read == 0 && mt->cache_write == 0) continue;
        char in_s[16], out_s[16], cr_s[16], cw_s[16];
        format_tokens(mt->input_tokens, in_s, sizeof(in_s));
        format_tokens(mt->output_tokens, out_s, sizeof(out_s));
        format_tokens(mt->cache_read, cr_s, sizeof(cr_s));
        format_tokens(mt->cache_write, cw_s, sizeof(cw_s));
        double cost = compute_cost(mt);
        total_cost += cost;

        attron(COLOR_PAIR(CP_MODEL));
        mvprintw(row, 4, "%-24s", mt->model);
        attroff(COLOR_PAIR(CP_MODEL));
        attron(COLOR_PAIR(CP_VALUE));
        mvprintw(row, 28, " %5d", mt->messages);
        mvprintw(row, 34, " %9s %9s %9s %9s", in_s, out_s, cr_s, cw_s);
        attroff(COLOR_PAIR(CP_VALUE));
        attron(COLOR_PAIR(CP_COST) | A_BOLD);
        mvprintw(row, 74, " $%7.2f", cost);
        attroff(COLOR_PAIR(CP_COST) | A_BOLD);
        row++;

        tot_in += mt->input_tokens;
        tot_out += mt->output_tokens;
        tot_cr += mt->cache_read;
        tot_cw += mt->cache_write;
        tot_msgs += mt->messages;
    }

    {
        char in_s[16], out_s[16], cr_s[16], cw_s[16];
        format_tokens(tot_in, in_s, sizeof(in_s));
        format_tokens(tot_out, out_s, sizeof(out_s));
        format_tokens(tot_cr, cr_s, sizeof(cr_s));
        format_tokens(tot_cw, cw_s, sizeof(cw_s));

        attron(COLOR_PAIR(CP_LABEL) | A_BOLD);
        mvprintw(row, 4, "%-24s", "TOTAL");
        attroff(COLOR_PAIR(CP_LABEL) | A_BOLD);
        attron(COLOR_PAIR(CP_VALUE) | A_BOLD);
        mvprintw(row, 28, " %5d", tot_msgs);
        mvprintw(row, 34, " %9s %9s %9s %9s", in_s, out_s, cr_s, cw_s);
        attroff(COLOR_PAIR(CP_VALUE) | A_BOLD);
        attron(COLOR_PAIR(CP_COST) | A_BOLD);
        mvprintw(row, 74, " $%7.2f", total_cost);
        attroff(COLOR_PAIR(CP_COST) | A_BOLD);
        row++;
    }

    return row;
}

static void draw_status(CmonState *st, int rows, int cols) {
    int row = rows - 1;
    draw_hline(row - 1, cols);

    attron(COLOR_PAIR(CP_DIM));
    char time_str[16] = "never";
    if (st->last_update > 0) {
        struct tm *tm = localtime(&st->last_update);
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm);
    }
    mvprintw(row, 2, "Last update: %s  |  Tracking %d files  |  %s",
             time_str, st->tracked_count,
             st->use_polling ? "polling" : "inotify");
    attroff(COLOR_PAIR(CP_DIM));
}

static void draw_screen(CmonState *st) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    if (rows < 10 || cols < 40) {
        clear();
        mvprintw(rows / 2, (cols - 20) / 2, "Terminal too small");
        mvprintw(rows / 2 + 1, (cols - 24) / 2, "Need at least 40x10");
        refresh();
        return;
    }

    erase();

    draw_header(cols);
    int row = draw_today(st, 1, cols);
    row = draw_daily_history(st, row, rows, cols);
    row = draw_alltime(st, row, cols);
    (void)row;
    draw_status(st, rows, cols);

    refresh();
}

/* ── Main ─────────────────────────────────────────────────────── */

int main(void) {
    setlocale(LC_ALL, "");

    CmonState st;
    init_state(&st);

    /* 0. Load dynamic pricing (fetches once per 24h, best-effort) */
    load_dynamic_pricing();

    /* 1. Parse historical data */
    parse_stats_cache(&st);

    /* 2. Scan historical JSONL files for per-day token breakdowns */
    scan_historical_sessions(&st);
    qsort(st.daily, st.daily_count, sizeof(DailyStats), cmp_daily_date_desc);

    /* 3. Set up inotify before scanning (so new files get watched) */
    setup_inotify(&st);

    /* 4. Scan today's JSONL files */
    scan_active_sessions(&st);

    /* 4. Init ncurses */
    initscr();
    cbreak();
    noecho();
    nodelay(stdscr, TRUE);
    keypad(stdscr, TRUE);
    curs_set(0);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(CP_HEADER, COLOR_WHITE, COLOR_BLUE);
        init_pair(CP_LABEL,  COLOR_CYAN,  -1);
        init_pair(CP_VALUE,  COLOR_WHITE, -1);
        init_pair(CP_COST,   COLOR_YELLOW, -1);
        init_pair(CP_LIVE,   COLOR_GREEN, -1);
        init_pair(CP_MODEL,  COLOR_MAGENTA, -1);
        init_pair(CP_BORDER, COLOR_BLUE, -1);
        init_pair(CP_DIM,    COLOR_WHITE, -1);
    }

    /* 5. Main loop */
    while (st.running) {
        /* Handle inotify/polling */
        handle_inotify_events(&st);

        /* Draw */
        draw_screen(&st);

        /* Handle input */
        int ch = getch();
        switch (ch) {
        case 'q':
        case 27: /* Escape */
            st.running = 0;
            break;
        case 'j':
        case KEY_DOWN:
            if (st.scroll_offset < st.max_scroll)
                st.scroll_offset++;
            break;
        case 'k':
        case KEY_UP:
            if (st.scroll_offset > 0)
                st.scroll_offset--;
            break;
        case 'r':
            parse_stats_cache(&st);
            scan_historical_sessions(&st);
            qsort(st.daily, st.daily_count, sizeof(DailyStats), cmp_daily_date_desc);
            scan_active_sessions(&st);
            break;
        }

        /* Sleep for tick interval */
        napms(TICK_MS);
    }

    /* 6. Cleanup */
    endwin();

    if (st.inotify_fd >= 0)
        close(st.inotify_fd);

    return 0;
}
