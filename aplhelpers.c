/* These are some functions to access struct fields. 
   The structs differ per platform and there's no way to see that from APL.
*/

#include <stdint.h>
#include <libssh2.h>

int8_t test() { return 42; }

uint64_t stat_size(libssh2_struct_stat *s) { return s->st_size; }
int32_t stat_mode(libssh2_struct_stat *s) { return s->st_mode; }
int64_t stat_atime(libssh2_struct_stat *s) { return s->st_atime; }
int64_t stat_mtime(libssh2_struct_stat *s) { return s->st_mtime; }

