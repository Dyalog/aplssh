/* These are some functions to access struct fields. 
   The structs differ per platform and there's no way to see that from APL.
*/


#include "aplhelpers.h"
#include <stdio.h>

// test function
int8_t   ADDCALL test() { return 42; }

// access libssh2_struct_stat fields
uint64_t ADDCALL stat_size(libssh2_struct_stat *s) { return s->st_size; }
int32_t  ADDCALL stat_mode(libssh2_struct_stat *s) { return s->st_mode; }
int64_t  ADDCALL stat_atime(libssh2_struct_stat *s) { return s->st_atime; }
int64_t  ADDCALL stat_mtime(libssh2_struct_stat *s) { return s->st_mtime; }

// access libssh2_knownhost fields
uint32_t ADDCALL knownhost_magic(struct libssh2_knownhost *k) { return k->magic; }
void*    ADDCALL knownhost_node(struct libssh2_knownhost *k) { return k->node; }
char*    ADDCALL knownhost_name(struct libssh2_knownhost *k) { return k->name; }
char*    ADDCALL knownhost_key(struct libssh2_knownhost *k) { return k->key; }
int32_t  ADDCALL knownhost_typemask(struct libssh2_knownhost *k) { return k->typemask; }

// getaddrinfo fields
int32_t ADDCALL apl_addr_family(struct apl_addr *r) { return r->family; }
int32_t ADDCALL apl_addr_socktype(struct apl_addr *r) { return r->socktype; }
uintptr_t ADDCALL apl_addr_addrlen(struct apl_addr *r) { return r->addrlen; }
char* ADDCALL apl_addr_canonname(struct apl_addr *r) { return r->canonname; }
struct sockaddr *ADDCALL apl_addr_sockaddr(struct apl_addr *r) { return r->addr; }
struct apl_addr *ADDCALL apl_addr_next(struct apl_addr *r) { return r->next; }

// getaddrinfo
int32_t  ADDCALL apl_getaddrinfo(int32_t family,
                                 char *hostname,
                                 char *srvport,
                                 uint8_t pasv,
                                 struct apl_addr **r) {
    int32_t retval; 

    // if no family is given, use all
    if (family==0) family=AF_UNSPEC;

    // if no hostname is given, set the passive flag
    pasv = pasv || strlen(hostname) == 0;
    
    *r=NULL;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints)); 
    hints.ai_family=family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_V4MAPPED;
    hints.ai_flags |= AI_CANONNAME; 
    hints.ai_flags |= AI_ADDRCONFIG;
    hints.ai_flags |= AI_PASSIVE * !!pasv;

    if (strlen(hostname) == 0) {
        // treat an empty string as if it were NULL
        retval = getaddrinfo(NULL, srvport, &hints, &res);
    } else {
        retval = getaddrinfo(hostname, srvport, &hints, &res);
    }
    
    if (retval==EAI_NONAME) {
        // for APL's sake, treat this as returning an "empty list" rather than
        // signaling an error that would differ by platform
        *r=NULL;

        return 0;
    }
    if (retval!=0) return retval; // error code

    *r = apl_addr_copydata(res);
    return 0;
}

// copy the data from addrinfo into apl_addrinfo
struct apl_addr *apl_addr_copydata(struct addrinfo *in) {
    // allocate a new object
    
    struct apl_addr *out_start, *out = alloc_apl_addr();
    out_start = out;

    while (in != NULL) {
        if (out == NULL) return NULL; // allocation failed

        out->family   = (int32_t)   in->ai_family;
        out->socktype = (int32_t)   in->ai_socktype;
        out->addrlen  = (uintptr_t) in->ai_addrlen;
        out->addr     =             in->ai_addr;
        if (in->ai_canonname == NULL) {
            out->canonname[0]='\0';
        } else {
            strncpy(out->canonname, in->ai_canonname, CANONNAME_LEN);
            out->canonname[CANONNAME_LEN-1]='\0';
        }

        // if there is a next one, copy that one
        in = in->ai_next;
        if (in != NULL) {
            out->next = alloc_apl_addr();
            out = out->next;
        } 
    }
    
    return out_start;
}

// allocate a new apl_addrinfo
struct apl_addr *alloc_apl_addr() {
    struct apl_addr *a;
    if (!(a = malloc(sizeof(struct apl_addr)))) return NULL;
    memset(a, 0, sizeof(struct apl_addr));
    return a;
}

// free them all
void ADDCALL apl_freeaddrinfo(struct apl_addr *addr) {
    do {
        struct apl_addr *next = addr->next;
        free(addr);
        addr = next;
    } while (addr != NULL);
}
