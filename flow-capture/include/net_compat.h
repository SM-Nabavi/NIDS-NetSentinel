#ifndef NIDS_NET_COMPAT_H
#define NIDS_NET_COMPAT_H

/* Define _WINSOCK_DEPRECATED_NO_WARNINGS to suppress deprecation warnings */
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#ifdef _WIN32
    /* Windows: include winsock2.h first, then ws2tcpip.h */
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <stdint.h>
    #include <stdbool.h>
    #include <stdio.h>   /* fprintf/stderr used below (WSAStartup/inet_ntop error logging) */
    #include <string.h>  /* memset used below */

    /* Define IP protocol numbers if not already defined */
    #ifndef IPPROTO_TCP
        #define IPPROTO_TCP 6
    #endif
    #ifndef IPPROTO_UDP
        #define IPPROTO_UDP 17
    #endif

    /* Define EtherType values if not already defined on Windows */
    #ifndef ETHERTYPE_IP
        #define ETHERTYPE_IP 0x0800
    #endif
    #ifndef ETHERTYPE_VLAN
        #define ETHERTYPE_VLAN 0x8100
    #endif

    /* Ethernet header (equivalent to netinet/if_ether.h) */
    struct ether_header {
        uint8_t ether_dhost[6];
        uint8_t ether_shost[6];
        uint16_t ether_type;
    };

    /* IPv4 header (equivalent to netinet/ip.h) */
    struct iphdr {
        uint8_t ihl:4;
        uint8_t version:4;
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    };

    /* TCP header (equivalent to netinet/tcp.h) */
    struct tcphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
        uint16_t res1:4;
        uint16_t doff:4;
        uint16_t fin:1;
        uint16_t syn:1;
        uint16_t rst:1;
        uint16_t psh:1;
        uint16_t ack:1;
        uint16_t urg:1;
        uint16_t res2:2;
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
    };

    /* UDP header (equivalent to netinet/udp.h) */
    struct udphdr {
        uint16_t source;
        uint16_t dest;
        uint16_t len;
        uint16_t check;
    };

    /*
     * Winsock must be initialized with WSAStartup() before any Winsock API
     * (including WSAAddressToStringA, used below) can be called. Npcap/pcap
     * capture does not initialize Winsock automatically, so without this,
     * every WSAAddressToStringA call below would fail with WSANOTINITIALISED.
     *
     * Call net_compat_wsa_init() once at process startup (before opening any
     * capture handle) and net_compat_wsa_cleanup() at shutdown.
     */
    static inline int net_compat_wsa_init(void) {
        static bool wsa_ready = false;
        if (wsa_ready) return 0;
        WSADATA wsa_data;
        int rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        if (rc != 0) {
            fprintf(stderr, "[net_compat ERROR] WSAStartup failed: %d\n", rc);
            return rc;
        }
        wsa_ready = true;
        return 0;
    }

    static inline void net_compat_wsa_cleanup(void) {
        WSACleanup();
    }

    /* Replacements for inet_ntop and inet_pton */
    static inline const char *inet_ntop_win(int af, const void *src, char *dst, socklen_t size) {
        /* Always leave the buffer in a defined, null-terminated state before
         * attempting the conversion, so a failure never propagates
         * uninitialized memory into a flow_id / JSON field. */
        if (dst && size > 0) {
            dst[0] = '\0';
        }

        if (af == AF_INET) {
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_addr = *(struct in_addr*)src;

            DWORD str_len = (DWORD)size;
            if (WSAAddressToStringA((struct sockaddr*)&sin, sizeof(sin), NULL, dst, &str_len) == 0) {
                return dst;
            }
            fprintf(stderr, "[net_compat ERROR] WSAAddressToStringA(AF_INET) failed: %d "
                            "(did you forget to call net_compat_wsa_init()?)\n", WSAGetLastError());
        } else if (af == AF_INET6) {
            struct sockaddr_in6 sin6;
            memset(&sin6, 0, sizeof(sin6));
            sin6.sin6_family = AF_INET6;
            sin6.sin6_addr = *(struct in6_addr*)src;

            DWORD str_len = (DWORD)size;
            if (WSAAddressToStringA((struct sockaddr*)&sin6, sizeof(sin6), NULL, dst, &str_len) == 0) {
                return dst;
            }
            fprintf(stderr, "[net_compat ERROR] WSAAddressToStringA(AF_INET6) failed: %d "
                            "(did you forget to call net_compat_wsa_init()?)\n", WSAGetLastError());
        }
        /* dst is already "" from the reset above -- never garbage. */
        return NULL;
    }
    #define inet_ntop(af, src, dst, size) inet_ntop_win(af, src, dst, size)

    static inline int inet_pton_win(int af, const char *src, void *dst) {
        if (af == AF_INET) {
            struct sockaddr_in sin;
            int len = sizeof(sin);
            if (WSAStringToAddressA((char*)src, AF_INET, NULL, (struct sockaddr*)&sin, &len) == 0) {
                *(struct in_addr*)dst = sin.sin_addr;
                return 1;
            }
        }
        return 0;
    }
    #define inet_pton(af, src, dst) inet_pton_win(af, src, dst)

#else
    /* Linux/Unix */
    #include <netinet/in.h>
    #include <netinet/if_ether.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <arpa/inet.h>
#endif

#endif /* NIDS_NET_COMPAT_H */