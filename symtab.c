/*
 * build symbol table of ELF
 *
 * Author: Wu Bingzheng
 *   Date: 2016-5
 */

#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <gelf.h>
#include <string.h>
#include <stdbool.h>

struct symbol_s {
	bool		is_lib;
	uintptr_t	address;
	size_t		size;
	char		*name;
};

static uintptr_t lib_start, lib_end;
static struct symbol_s symbol_table[10000];
static int symbol_count;

static int symtab_build_section(Elf *elf, Elf_Scn *section,
		uintptr_t offset, uintptr_t base_addr)
{
	GElf_Shdr shdr;
	if (gelf_getshdr(section, &shdr) == NULL) {
		return 0;
	}

	if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) {
		return 0;
	}

	Elf_Data *data = elf_getdata(section, NULL);
	if (data == NULL || data->d_size == 0) {
		return 0;
	}

	int i, count = 0;
	GElf_Sym esym;
	for (i = 0; gelf_getsym(data, i, &esym) != NULL; i ++) {
		if ((esym.st_value == 0) || (esym.st_size == 0) ||
				(esym.st_shndx == SHN_UNDEF) ||
#ifdef STB_NUM
				(GELF_ST_BIND(esym.st_info) == STB_NUM) ||
#endif
				(GELF_ST_TYPE(esym.st_info) != STT_FUNC)) {
			continue;
		}

		struct symbol_s *sym = &symbol_table[symbol_count++];

		sym->is_lib = false;
		sym->name = strdup(elf_strptr(elf, shdr.sh_link, (size_t)esym.st_name));
		sym->address = esym.st_value - base_addr + offset;
		sym->size = esym.st_size;

		count++;
	}
	return count;
}

static int symtab_build_file(const char *path, uintptr_t start, uintptr_t end)
{
	/* open file */
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return -1;
	}

	elf_version(EV_CURRENT);
	Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		close(fd);
		return -1;
	}

	GElf_Ehdr hdr;
	gelf_getehdr(elf, &hdr);
	if (hdr.e_type == ET_DYN) {
		return 0;
	}

	/* find symbol section */
	Elf_Scn* section = NULL;
	int count = 0;
	while ((section = elf_nextscn(elf, section)) != NULL) {
		count += symtab_build_section(elf, section, 0, 0);
	}

	/* clean up */
	elf_end(elf);
	close(fd);
	return count;
}

static int symbol_cmp(const void *a, const void *b)
{
	const struct symbol_s *sa = a;
	const struct symbol_s *sb = b;
	return sa->address < sb->address ? -1 : 1;
}

static const char *proc_maps(pid_t pid, size_t *start, size_t *end, int *exe_self)
{
	static FILE *filp = NULL;
	static char exe_name[1024];
	static char ret_path[1024];

	/* first, init */
	if (filp == NULL) {
		char pname[100];
		sprintf(pname, "/proc/%d/maps", pid);
		filp = fopen(pname, "r");
		if (filp == NULL) {
			perror("Error in open /proc/pid/maps");
			exit(3);
		}

		sprintf(pname, "/proc/%d/exe", pid);
		int exe_len = readlink(pname, exe_name, sizeof(exe_name));
		if (exe_len < 0) {
			perror("error in open /proc/pid/exe");
			exit(3);
		}
		exe_name[exe_len] = '\0';
	}

	/* walk through */
	char line[1024];
	char perms[5];
	char deleted[100];
	int ia, ib, ic, id;
	while (fgets(line, sizeof(line), filp) != NULL) {
		int ret = sscanf(line, "%zx-%zx %s %x %x:%x %d %s %s",
				start, end, perms, &ia, &ib, &ic, &id, ret_path, deleted);
		if (ret == 8 && perms[2] == 'x' && ret_path[0] == '/') {
			if (exe_self != NULL) {
				*exe_self = (strcmp(ret_path, exe_name) == 0);
			}
			return ret_path;
		}
	}

	fclose(filp);
	filp = NULL;
	return NULL;
}

int symtab_build(pid_t pid)
{
	const char *path;
	size_t start, end;
	int exe_self, count = 0;
	while ((path = proc_maps(pid, &start, &end, &exe_self)) != NULL) {

		if (exe_self) {
			count = symtab_build_file(path, start, end);

		} else {
			struct symbol_s *sym = &symbol_table[symbol_count++];
			sym->is_lib = true;
			sym->name = strdup(path);
			sym->address = start;
			sym->size = end - start;
		}
	}

	/* finish */
	qsort(symbol_table, symbol_count, sizeof(struct symbol_s), symbol_cmp);
	return count;
}

const char *symtab_get(uintptr_t address, int *offset, bool *is_lib)
{
	int min = 0, max = symbol_count - 1;
	while (min <= max) {
		int mid = (min + max) / 2;
		struct symbol_s *sym = &symbol_table[mid];
		if (address < sym->address) {
			max = mid - 1;
		} else if (address >= sym->address + sym->size) {
			min = mid + 1;
		} else {
			*offset = address - sym->address;
			*is_lib = sym->is_lib;
			return sym->name;
		}
	}
	return NULL;
}

bool symtab_is_lib(uintptr_t address)
{
	return (address >= lib_start) && (address <= lib_end);
}
