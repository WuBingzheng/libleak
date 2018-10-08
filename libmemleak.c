#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <libunwind.h>
#include <sys/types.h>
#include <unistd.h>

#include "wuy_dict.h"
#include "wuy_list.h"
#include "wuy_pool.h"

#include "symtab.h"


static bool leak_inited;

static __thread bool leak_in_process;

static void *(*leak_real_malloc)(size_t size);
static void (*leak_real_free)(void *ptr);
static void *(*leak_real_calloc)(size_t nmemb, size_t size);
static void *(*leak_real_realloc)(void *ptr, size_t size);

static FILE *leak_log_filp;


struct leak_callstack {
	int		id;

	int		alloc_count, free_count;
	int		expired_count, free_expired_count;
	size_t		alloc_size, free_size;
	size_t		expired_size, free_expired_size;
	time_t		free_min, free_max, free_total;
	time_t		unfree_max;

	wuy_dict_node_t	dict_node;

	pthread_mutex_t	mutex;

	int		ip_num;
	unw_word_t	ips[0];
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
		hash ^= wuy_dict_hash_pointer(&cs->ips[i]);
	}
	return hash;
}
static bool leak_callstack_equal(const void *a, const void *b)
{
	const struct leak_callstack *csa = a;
	const struct leak_callstack *csb = b;
	return (csa->ip_num == csb->ip_num) &&
		(memcmp(csa->ips, csb->ips, sizeof(unw_word_t) * csa->ip_num) == 0);
}

static void leak_callstack_print(struct leak_callstack *cs)
{
	for (int i = 0; i < cs->ip_num; i++) {
		uintptr_t address = cs->ips[i];
		if (address == 0) {
			break;
		}

		int offset;
		bool is_lib;
		const char *proc_name = symtab_get(address, &offset, &is_lib);

		if (proc_name == NULL) {
			fprintf(leak_log_filp, "    0x%016zx\n", address);
		} else if (is_lib) {
			fprintf(leak_log_filp, "    0x%016zx  %s\n", address, proc_name);
		} else {
			fprintf(leak_log_filp, "    0x%016zx  %s()+%d\n", address, proc_name, offset);
			if (strcmp(proc_name, "main") == 0) {
				break;
			}
		}
	}
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


static void __attribute__((constructor))init(void)
{
	/* symbols */
	leak_real_malloc = dlsym(RTLD_NEXT, "malloc");
	assert(leak_real_malloc != NULL);

	leak_real_realloc = dlsym(RTLD_NEXT, "realloc");
	assert(leak_real_realloc != NULL);

	leak_real_calloc = dlsym(RTLD_NEXT, "calloc");
	assert(leak_real_calloc != NULL);

	leak_real_free = dlsym(RTLD_NEXT, "free");
	assert(leak_real_free != NULL);

	/**/
	leak_callstack_dict = wuy_dict_new_func(leak_callstack_hash,
			leak_callstack_equal,
			offsetof(struct leak_callstack, dict_node));

	leak_memblock_dict = wuy_dict_new_func(leak_memblock_hash,
			leak_memblock_equal,
			offsetof(struct leak_memblock, dict_node));

	leak_memblock_pool = wuy_pool_new_type(struct leak_memblock);

	/* log file */
	pid_t pid = getpid();
	char log_fname[100];
	sprintf(log_fname, "/tmp/libmemleak.%d", pid);
	leak_log_filp = fopen(log_fname, "w");
	assert(leak_log_filp != NULL);

	/* debug info */
	int count = symtab_build(pid);
	fprintf(leak_log_filp, "load symbols: %d\n", count);

	leak_inited = true;
}

static void leak_routine(void)
{
	time_t now = time(NULL);

	if (leak_in_process) {
		return;
	}

	if (pthread_mutex_trylock(&leak_memblock_mutex) != 0) {
		return;
	}

	leak_in_process = true;

	wuy_list_node_t *node, *safe;
	wuy_list_iter_safe(&leak_memblock_list, node, safe) {
		struct leak_memblock *mb = wuy_containerof(node, struct leak_memblock, list_node);
		if (now - mb->create < 10) {
			break;
		}

		struct leak_callstack *cs = mb->callstack;
		cs->expired_count++;
		cs->expired_size += mb->size;

		if (cs->expired_count == 1) {
			fprintf(leak_log_filp, "callstack[%d] expires (size=%ld) first time:\n",
					cs->id, mb->size);
			leak_callstack_print(cs);
		} else {
			fprintf(leak_log_filp, "callstack[%d] expires (size=%ld,%ld) again: %d\n",
					cs->id, mb->size, cs->expired_size, cs->expired_count);
		}

		mb->expired = true;
		wuy_list_del_init(&mb->list_node);
	}
	pthread_mutex_unlock(&leak_memblock_mutex);

	fflush(leak_log_filp);

	leak_in_process = false;
}


static int leak_unwind(unw_word_t *ips, int size)
{
	int i = 0;
	unw_context_t context;
	unw_getcontext(&context);
	unw_cursor_t cursor;
	unw_init_local(&cursor, &context);
	do {
		unw_get_reg(&cursor, UNW_REG_IP, &ips[i++]);
	} while (i < size && unw_step(&cursor) > 0);
	return i;
}

static struct leak_callstack *leak_current(void)
{
	static int leak_callstack_id = 1;

	struct leak_callstack current[20];
	current->ip_num = leak_unwind(current->ips, 100);

	if (current->ip_num == 0) {
		return NULL;
	}

	pthread_mutex_lock(&leak_callstack_mutex);

	struct leak_callstack *cs = wuy_dict_get(leak_callstack_dict, current);
	if (cs != NULL) {
		pthread_mutex_unlock(&leak_callstack_mutex);
		return cs;
	}

	cs = leak_real_calloc(1, sizeof(struct leak_callstack) + sizeof(unw_word_t) * current->ip_num);
	cs->id = leak_callstack_id++;
	cs->ip_num = current->ip_num;
	pthread_mutex_init(&cs->mutex, NULL);
	cs->free_min = 1000;
	memcpy(cs->ips, current->ips, sizeof(unw_word_t) * current->ip_num);
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
	}

	time_t t = time(NULL) - mb->create;
	if (t > cs->free_max) {
		cs->free_max = t;
	}
	if (t < cs->free_min) {
		cs->free_min = t;
	}
	cs->free_total += t;
	pthread_mutex_unlock(&cs->mutex);

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

	leak_in_process = false;
}

void *malloc(size_t size)
{
	leak_routine();

	void *p = leak_real_malloc(size);

	leak_process_alloc(p, size);

	return p;
}

void free(void *p)
{
	leak_routine();

	leak_real_free(p);

	leak_process_free(p);
}

void *calloc(size_t nmemb, size_t size)
{
	leak_routine();

	void *p = leak_real_calloc(nmemb, size);

	leak_process_alloc(p, nmemb * size);

	return p;
}

void *realloc(void *ptr, size_t size)
{
	leak_routine();

	void *newp = leak_real_realloc(ptr, size);

	if (newp == ptr) {
		leak_process_update(ptr, size);
	} else {
		leak_process_free(ptr);
		leak_process_alloc(newp, size);
	}

	return newp;
}
