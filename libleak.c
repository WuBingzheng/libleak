#define _GNU_SOURCE

#include <execinfo.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* libwuya */
#include "wuy_dict.h"
#include "wuy_list.h"
#include "wuy_pool.h"


/* ### configuration from environment variables */

/* LEAK_EXPIRE: log if a memory block is not freed after this time.
 * You should change this according to your scenarios. */
static time_t conf_expire = 60;

/* LEAK_AUTO_EXPIRE: increase 'expire' if any block is freed
 * after expired, if set. */
static bool conf_auto_expire = false;

/* LEAK_PID_CHECK: interval to check conf_pid_file to enable
 * detectiong. Only useful for multi-process program.
 * 0 means no checking and detect all processes. */
static time_t conf_pid_check = 0;

/* LEAK_PID_FILE: each line contains a pid to detect. */
static char *conf_pid_file = "/tmp/libleak.enabled";

/* LEAK_LOG_FILE: log file name. */
static char *conf_log_file = "/tmp/libleak";


/* ### hooking symbols */
static void *(*leak_real_malloc)(size_t size);
static void (*leak_real_free)(void *ptr);
static void *(*leak_real_calloc)(size_t nmemb, size_t size);
static void *(*leak_real_realloc)(void *ptr, size_t size);
static pid_t (*leak_real_fork)(void); /* open new log file for new process */


/* ### running flags */
static bool leak_inited;
static __thread bool leak_in_process;
static FILE *leak_log_filp;


/* ### structures and utils for call-stack and memory-block */

struct leak_callstack {
	int		id;

	int		alloc_count, free_count;
	int		expired_count, free_expired_count;
	size_t		alloc_size, free_size;
	size_t		expired_size, free_expired_size;
	time_t		free_min, free_max, free_total;

	wuy_list_t	expired_list;
	wuy_dict_node_t	dict_node;

	pthread_mutex_t	mutex;

	int		ip_num;
	void		*ips[0];
};
static wuy_dict_t *leak_callstack_dict;
static pthread_mutex_t leak_callstack_mutex = PTHREAD_MUTEX_INITIALIZER;


struct leak_memblock {
	void		*address;
	size_t		size;
	time_t		create;
	wuy_dict_node_t	dict_node;
	wuy_list_node_t	list_node;

	bool		expired;

	struct leak_callstack *callstack;
};
static wuy_pool_t *leak_memblock_pool;
static wuy_dict_t *leak_memblock_dict;
static WUY_LIST(leak_memblock_list);
static pthread_mutex_t leak_memblock_mutex = PTHREAD_MUTEX_INITIALIZER;


static uint32_t leak_callstack_hash(const void *item)
{
	const struct leak_callstack *cs = item;
	uint32_t hash = cs->ip_num;
	for (int i = 0; i < cs->ip_num; i++) {
		hash ^= wuy_dict_hash_pointer((void *)cs->ips[i]);
	}
	return hash;
}
static bool leak_callstack_equal(const void *a, const void *b)
{
	const struct leak_callstack *csa = a;
	const struct leak_callstack *csb = b;
	return (csa->ip_num == csb->ip_num) &&
		(memcmp(csa->ips, csb->ips, sizeof(void *) * csa->ip_num) == 0);
}
static int leak_callstack_cmp(const void *a, const void *b)
{
	const struct leak_callstack *csa = *(const struct leak_callstack **)a;
	const struct leak_callstack *csb = *(const struct leak_callstack **)b;
	return (csa->expired_count - csa->free_expired_count)
		- (csb->expired_count - csb->free_expired_count);
}

static void leak_callstack_print(struct leak_callstack *cs)
{
	char **symbols = backtrace_symbols(cs->ips, cs->ip_num);

	for (int i = 2; i < cs->ip_num; i++) {
		fprintf(leak_log_filp, "    %s\n", symbols[i]);
	}

	free(symbols);
}


static uint32_t leak_memblock_hash(const void *item)
{
	const struct leak_memblock *mb = item;
	return wuy_dict_hash_pointer(mb->address);
}
static bool leak_memblock_equal(const void *a, const void *b)
{
	const struct leak_memblock *mba = a;
	const struct leak_memblock *mbb = b;
	return mba->address == mbb->address;
}


/* ### a simple memory allocation used before init() */

static uint8_t tmp_buffer[1024 * 1024]; /* increase this if need */
static uint8_t *tmp_buf_pos = tmp_buffer;
static void *tmp_malloc(size_t size)
{
	size = (size + 7) / 8 * 8;
	if (size > sizeof(tmp_buffer) - (tmp_buf_pos - tmp_buffer)) {
		abort();
	}
	void *p = tmp_buf_pos;
	tmp_buf_pos += size;
	return p;
}
static void *tmp_calloc(size_t n, size_t size)
{
	void *p = tmp_malloc(n * size);
	bzero(p, n * size);
	return p;
}
static void *tmp_realloc(void *oldp, size_t size)
{
	void *newp = tmp_malloc(size);
	memcpy(newp, oldp, size);
	return newp;
}
static bool tmp_free(void *p)
{
	return (p >= (void *)tmp_buffer) && (p <= (void *)tmp_buffer + sizeof(tmp_buffer));
}


/* ### report statistics on exiting */
static void leak_report(void)
{
	fprintf(leak_log_filp, "\n# callstack statistics: (in ascending order)\n\n");

	struct leak_callstack *callstacks[wuy_dict_count(leak_callstack_dict)];

	int count = 0;
	wuy_dict_node_t *node;
	wuy_dict_iter(leak_callstack_dict, node) {
		struct leak_callstack *cs = wuy_containerof(node,
				struct leak_callstack, dict_node);
		if (cs->expired_count == cs->free_expired_count) {
			continue;
		}
		callstacks[count++] = cs;
	}

	qsort(callstacks, count, sizeof(struct leak_callstack *), leak_callstack_cmp);

	time_t now = time(NULL);

	for (int i = 0; i < count; i++) {
		struct leak_callstack *cs = callstacks[i];

		time_t unfree_max = 0;
		if (!wuy_list_empty(&cs->expired_list)) {
			struct leak_memblock *mb = wuy_containerof(
				wuy_list_first(&cs->expired_list),
				struct leak_memblock, list_node);
			unfree_max = now - mb->create;
		}
		fprintf(leak_log_filp, "callstack[%d]: may-leak=%d (%ld bytes)\n"
                                "    expired=%d (%ld bytes), free_expired=%d (%ld bytes)\n"
                                "    alloc=%d (%ld bytes), free=%d (%ld bytes)\n"
                                "    freed memory live time: min=%ld max=%ld average=%ld\n"
                                "    un-freed memory live time: max=%ld\n",
                                cs->id,
                                cs->expired_count - cs->free_expired_count,
                                cs->expired_size - cs->free_expired_size,
                                cs->expired_count, cs->expired_size,
                                cs->free_expired_count, cs->free_expired_size,
                                cs->alloc_count, cs->alloc_size,
                                cs->free_count, cs->free_size,
                                cs->free_min, cs->free_max,
                                cs->free_count ? cs->free_total / cs->free_count : 0,
                                unfree_max);
	}
}


/* ### module init */
static void __attribute__((constructor))init(void)
{
	/* read configs from environment variables */
	char *ev = getenv("LEAK_EXPIRE");
	if (ev != NULL) {
		conf_expire = atoi(ev);
	}
	ev = getenv("LEAK_AUTO_EXPIRE");
	if (ev != NULL) {
		conf_auto_expire = true;
	}
	ev = getenv("LEAK_LOG_FILE");
	if (ev != NULL) {
		conf_log_file = strdup(ev);
	}
	ev = getenv("LEAK_PID_CHECK");
	if (ev != NULL) {
		conf_pid_check = atoi(ev);
	}
	ev = getenv("LEAK_PID_FILE");
	if (ev != NULL) {
		conf_pid_file = strdup(ev);
	}

	/* hook symbols */
	leak_real_malloc = dlsym(RTLD_NEXT, "malloc");
	assert(leak_real_malloc != NULL);

	leak_real_realloc = dlsym(RTLD_NEXT, "realloc");
	assert(leak_real_realloc != NULL);

	leak_real_calloc = dlsym(RTLD_NEXT, "calloc");
	assert(leak_real_calloc != NULL);

	leak_real_free = dlsym(RTLD_NEXT, "free");
	assert(leak_real_free != NULL);

	leak_real_fork = dlsym(RTLD_NEXT, "fork");
	assert(leak_real_fork != NULL);

	/* init dict and memory pool */
	leak_callstack_dict = wuy_dict_new_func(leak_callstack_hash,
			leak_callstack_equal,
			offsetof(struct leak_callstack, dict_node));

	leak_memblock_dict = wuy_dict_new_func(leak_memblock_hash,
			leak_memblock_equal,
			offsetof(struct leak_memblock, dict_node));

	leak_memblock_pool = wuy_pool_new_type(struct leak_memblock);

	/* log file */
	char log_fname[100];
	sprintf(log_fname, "%s.%d", conf_log_file, getpid());
	leak_log_filp = fopen(log_fname, "w");
	assert(leak_log_filp != NULL);

	/* report at exit */
	atexit(leak_report);

	fprintf(leak_log_filp, "# start detect. expire=%lds\n", conf_expire);
	fflush(leak_log_filp);

	leak_inited = true;
}


/* ### check, expire and log memory blocks */
static void leak_expire(void)
{
	time_t now = time(NULL);

	if (pthread_mutex_trylock(&leak_memblock_mutex) != 0) {
		return;
	}

	wuy_list_node_t *node, *safe;
	wuy_list_iter_safe(&leak_memblock_list, node, safe) {
		struct leak_memblock *mb = wuy_containerof(node, struct leak_memblock, list_node);
		if (now - mb->create < conf_expire) {
			break;
		}

		mb->expired = true;
		wuy_list_delete(&mb->list_node);

		struct leak_callstack *cs = mb->callstack;

		pthread_mutex_lock(&cs->mutex);
		cs->expired_count++;
		cs->expired_size += mb->size;
		wuy_list_append(&cs->expired_list, &mb->list_node);
		pthread_mutex_unlock(&cs->mutex);

		fprintf(leak_log_filp, "callstack[%d] expires. count=%d size=%ld/%ld alloc=%d free=%d\n",
				cs->id, cs->expired_count, mb->size, cs->expired_size,
				cs->alloc_count, cs->free_count);

		if ((cs->expired_count % 100) == 1) {
			/* print callstack once every 100 expiration */
			leak_callstack_print(cs);
		}
	}
	pthread_mutex_unlock(&leak_memblock_mutex);

	fflush(leak_log_filp);
}


/* ### check LEAK_PID_FILE to enable/disable detectiong current process */
static bool leak_enabled_check(void)
{
	/* enable all processes if LEAK_PID_CHECK is not set */
	if (conf_pid_check == 0) {
		return true;
	}

	static bool leak_enabled = false;

	static time_t last_check;

	time_t now = time(NULL);
	if (now - last_check < conf_pid_check) {
		return leak_enabled;
	}

	last_check = now;

	FILE *fp = fopen(conf_pid_file, "r");
	if (fp == NULL) {
		return leak_enabled;
	}

	bool old = leak_enabled;
	leak_enabled = false; /* disable if the pid is not found in file later */

	pid_t pid_enabled, pid_self = getpid();
	while (fscanf(fp, "%d", &pid_enabled) == 1) {
		if (pid_enabled == pid_self) {
			leak_enabled = true; /* enable! */
			break;
		}
	}
	fclose(fp);

	if (old ^ leak_enabled) {
		if (!leak_enabled) {
			leak_report();
		}

		fprintf(leak_log_filp, "# switch %s.\n", leak_enabled ? "enabled" : "disabled");
		fflush(leak_log_filp);
	}

	return leak_enabled;
}


static struct leak_callstack *leak_current(void)
{
	static int leak_callstack_id = 1;

	struct leak_callstack current[20];
	current->ip_num = backtrace(current->ips, 100);

	if (current->ip_num == 0) {
		return NULL;
	}

	pthread_mutex_lock(&leak_callstack_mutex);

	struct leak_callstack *cs = wuy_dict_get(leak_callstack_dict, current);
	if (cs != NULL) {
		pthread_mutex_unlock(&leak_callstack_mutex);
		return cs;
	}

	cs = leak_real_calloc(1, sizeof(struct leak_callstack) + sizeof(void *) * current->ip_num);
	cs->id = leak_callstack_id++;
	cs->ip_num = current->ip_num;
	pthread_mutex_init(&cs->mutex, NULL);
	memcpy(cs->ips, current->ips, sizeof(void *) * current->ip_num);
	wuy_list_init(&cs->expired_list);
	wuy_dict_add(leak_callstack_dict, cs);

	pthread_mutex_unlock(&leak_callstack_mutex);
	return cs;
}

static void leak_process_alloc(void *p, size_t size)
{
	if (!leak_inited) {
		return;
	}
	if (leak_in_process) {
		return;
	}
	leak_in_process = true;

	if (!leak_enabled_check()) {
		leak_in_process = false;
		return;
	}

	struct leak_callstack *cs = leak_current();
	if (cs == NULL) {
		leak_in_process = false;
		return;
	}

	pthread_mutex_lock(&cs->mutex);
	cs->alloc_size += size;
	cs->alloc_count++;
	pthread_mutex_unlock(&cs->mutex);

	pthread_mutex_lock(&leak_memblock_mutex);
	struct leak_memblock *mb = wuy_pool_alloc(leak_memblock_pool);
	mb->address = p;
	mb->size = size;
	mb->expired = false;
	mb->create = time(NULL);
	mb->callstack = cs;

	wuy_dict_add(leak_memblock_dict, mb);
	wuy_list_append(&leak_memblock_list, &mb->list_node);
	pthread_mutex_unlock(&leak_memblock_mutex);

	leak_expire();

	leak_in_process = false;
}

static void leak_process_free(void *p)
{
	if (!leak_inited) {
		return;
	}
	if (leak_in_process) {
		return;
	}
	leak_in_process = true;

	if (!leak_enabled_check()) {
		leak_in_process = false;
		return;
	}

	pthread_mutex_lock(&leak_memblock_mutex);
	struct leak_memblock key = { .address = p };
	struct leak_memblock *mb = wuy_dict_get(leak_memblock_dict, &key);
	if (mb == NULL) {
		pthread_mutex_unlock(&leak_memblock_mutex);
		leak_in_process = false;
		return;
	}
	wuy_dict_delete(leak_memblock_dict, mb);
	wuy_list_delete(&mb->list_node);
	struct leak_memblock tmp = *mb;
	wuy_pool_free(mb);
	mb = &tmp;
	pthread_mutex_unlock(&leak_memblock_mutex);

	/* update callstack stats */
	struct leak_callstack *cs = mb->callstack;
	pthread_mutex_lock(&cs->mutex);
	cs->free_count++;
	cs->free_size += mb->size;

	if (mb->expired) {
		cs->free_expired_count++;
		cs->free_expired_size += mb->size;

		time_t live = time(NULL) - mb->create;
		fprintf(leak_log_filp, "callstack[%d] frees after expired."
				" live=%ld expired=%d free_expired=%d\n",
				cs->id, live, cs->expired_count, cs->free_expired_count);

		if (conf_auto_expire && live > conf_expire) {
			fprintf(leak_log_filp, "# increase expire from %ld to %ld.\n",
					conf_expire, live);

			conf_expire = live;
		}

		fflush(leak_log_filp);
	}

	time_t t = time(NULL) - mb->create;
	if (t > cs->free_max) {
		cs->free_max = t;
	}
	if (cs->free_min == 0 || t < cs->free_min) {
		cs->free_min = t;
	}
	cs->free_total += t;
	pthread_mutex_unlock(&cs->mutex);

	leak_expire();

	leak_in_process = false;
}

static void leak_process_update(void *p, size_t size)
{
	if (!leak_inited) {
		return;
	}
	if (leak_in_process) {
		return;
	}
	leak_in_process = true;

	if (!leak_enabled_check()) {
		leak_in_process = false;
		return;
	}

	pthread_mutex_lock(&leak_memblock_mutex);
	struct leak_memblock key = { .address = p };
	struct leak_memblock *mb = wuy_dict_get(leak_memblock_dict, &key);
	if (mb == NULL) {
		pthread_mutex_unlock(&leak_memblock_mutex);
		leak_in_process = false;
		return;
	}
	mb->callstack->alloc_size += size - mb->size;
	mb->size = size;
	pthread_mutex_unlock(&leak_memblock_mutex);

	leak_expire();

	leak_in_process = false;
}

void *malloc(size_t size)
{
	if (leak_real_malloc == NULL) {
		return tmp_malloc(size);
	}

	void *p = leak_real_malloc(size);

	leak_process_alloc(p, size);

	return p;
}

void free(void *p)
{
	if (p == NULL) {
		return;
	}

	if (tmp_free(p)) {
		return;
	}

	leak_real_free(p);

	leak_process_free(p);
}

void *calloc(size_t nmemb, size_t size)
{
	if (leak_real_calloc == NULL) {
		return tmp_calloc(nmemb, size);
	}

	void *p = leak_real_calloc(nmemb, size);

	leak_process_alloc(p, nmemb * size);

	return p;
}

void *realloc(void *ptr, size_t size)
{
	if (ptr == NULL) {
		return malloc(size);
	}
	if (tmp_free(ptr)) {
		return tmp_realloc(ptr, size);
	}

	void *newp = leak_real_realloc(ptr, size);

	if (newp == ptr) {
		leak_process_update(ptr, size);
	} else {
		leak_process_free(ptr);
		leak_process_alloc(newp, size);
	}

	return newp;
}

pid_t fork(void)
{
	pid_t pid = leak_real_fork();
	if (pid == 0) {
		fclose(leak_log_filp);

		char log_fname[100];
		sprintf(log_fname, "%s.%d", conf_log_file, getpid());
		leak_log_filp = fopen(log_fname, "w");
		assert(leak_log_filp != NULL);

		fprintf(leak_log_filp, "# start detect. parent=%d expire=%lds\n",
				getppid(), conf_expire);
		fflush(leak_log_filp);
	}
	return pid;
}
