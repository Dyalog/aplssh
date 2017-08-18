/* These are some functions to access struct fields.
   The structs differ per platform and there's no way to see that from APL.

   These functions return the fields in variables of specified sizes, which
   are (for now at least) big enough on all platforms.
*/

#ifndef __APLHELPERS_H__

#include <stdint.h>
#include <libssh2.h>

#ifdef _WIN32
    // allow building on Windows
    #define ADDAPI __declspec(dllexport)
    #define ADDCALL __cdecl
#else
    // Unix doesn't need thes
    #define ADDAPI
    #define ADDCALL
#endif

ADDAPI int8_t   ADDCALL test();
ADDAPI uint64_t ADDCALL stat_size(libssh2_struct_stat *s);
ADDAPI int32_t  ADDCALL stat_mode(libssh2_struct_stat *s);
ADDAPI int64_t  ADDCALL stat_atime(libssh2_struct_stat *s);
ADDAPI int64_t  ADDCALL stat_mtime(libssh2_struct_stat *s);

#endif

