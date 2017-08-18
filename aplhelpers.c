/* These are some functions to access struct fields. 
   The structs differ per platform and there's no way to see that from APL.
*/


#include "aplhelpers.h"

int8_t   ADDCALL test() { return 42; }

uint64_t ADDCALL stat_size(libssh2_struct_stat *s) { return s->st_size; }
int32_t  ADDCALL stat_mode(libssh2_struct_stat *s) { return s->st_mode; }
int64_t  ADDCALL stat_atime(libssh2_struct_stat *s) { return s->st_atime; }
int64_t  ADDCALL stat_mtime(libssh2_struct_stat *s) { return s->st_mtime; }

