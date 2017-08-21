#include <stdio.h>

#include "aplhelpers.h"

void test_apl_getaddrinfo() {
    struct apl_addr *r;
    fprintf(stderr,"Running: ");
    int i = apl_getaddrinfo(0, "www.google.com", "80", 0, &r);
    fprintf(stderr,"%d\n", i);

    while (r) {
        fprintf(stderr,"Found: %d %d %ld - %s\n", r->family, r->socktype, r->addrlen, r->canonname);
        r=r->next;
    }

    fprintf(stderr,"Done.\n");

}

int main() {
    test_apl_getaddrinfo();
}
