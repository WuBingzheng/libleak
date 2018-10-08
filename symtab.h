
int symtab_build(pid_t pid);
const char *symtab_get(uintptr_t address, int *offset, bool *is_lib);
bool symtab_is_lib(uintptr_t address);
