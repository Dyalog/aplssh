/* These are some functions to access struct fields.
   The structs differ per platform and there's no way to see that from APL.

   These functions return the fields in variables of specified sizes, which
   are (for now at least) big enough on all platforms.
*/

#ifndef __APLSSH_HELPERS_H__
#define __APLSSH_HELPERS_H__

#include <stdint.h>
#include <libssh2.h>
#include <stdlib.h>

#include <sys/types.h>

#ifdef _WIN32
    // allow building on Windows
    #define ADDAPI __declspec(dllexport)
    #define ADDCALL __cdecl
    
    // Windows socket imports 
    #include <winsock2.h>
    #include <mswsock.h>
    
    #ifndef EAI_NONAME 
        #define EAI_NONAME WSAHOST_NOT_FOUND
    #endif 
#else
    // Unix socket imports
    #include <sys/socket.h>
    #include <netdb.h>

    // Unix doesn't need these
    #define ADDAPI
    #define ADDCALL
#endif

ADDAPI int8_t    ADDCALL test();

// access libssh2_struct_stat fields
ADDAPI uint64_t  ADDCALL stat_size(libssh2_struct_stat *s);
ADDAPI int32_t   ADDCALL stat_mode(libssh2_struct_stat *s);
ADDAPI int64_t   ADDCALL stat_atime(libssh2_struct_stat *s);
ADDAPI int64_t   ADDCALL stat_mtime(libssh2_struct_stat *s);

// access libssh2_knownhost fields
ADDAPI uint32_t  ADDCALL knownhost_magic(struct libssh2_knownhost *k);
ADDAPI void*     ADDCALL knownhost_node(struct libssh2_knownhost *k);
ADDAPI char*     ADDCALL knownhost_name(struct libssh2_knownhost *k);
ADDAPI char*     ADDCALL knownhost_key(struct libssh2_knownhost *k);
ADDAPI int32_t   ADDCALL knownhost_typemask(struct libssh2_knownhost *k);



// getaddrinfo wrapper with fixed-size arguments
#define CANONNAME_LEN 256
struct apl_addr {
    int32_t          family;                   // I4
    int32_t          socktype;                 // I4
    uintptr_t        addrlen;                  // P
    char             canonname[CANONNAME_LEN]; // 0C[256]
    struct sockaddr *addr;                     // P
    struct apl_addr *next;                     // P
};

// struct wrappers
ADDAPI int32_t   ADDCALL apl_addr_family(struct apl_addr *r);
ADDAPI int32_t   ADDCALL apl_addr_socktype(struct apl_addr *r);
ADDAPI uintptr_t ADDCALL apl_addr_addrlen(struct apl_addr *r);
ADDAPI char*     ADDCALL apl_addr_canonname(struct apl_addr *r); 
ADDAPI struct sockaddr *ADDCALL apl_addr_sockaddr(struct apl_addr *addr);
ADDAPI struct apl_addr *ADDCALL apl_addr_next(struct apl_addr *addr);

ADDAPI int32_t   ADDCALL apl_getaddrinfo(int32_t family, char *hostname, 
                            char *srvport, uint8_t pasv, struct apl_addr **r);
ADDAPI void      ADDCALL apl_freeaddrinfo(struct apl_addr *addr);

struct apl_addr *apl_addr_copydata(struct addrinfo *in);
struct apl_addr *alloc_apl_addr();
void apl_freeaddrinfo(struct apl_addr *addr);

#endif

