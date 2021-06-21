#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
    #include <process.h>         /* _getpid() */
    #include <winsock2.h>
    #include <ws2tcpip.h>        /* getaddrinfo() */
    typedef SOCKET socket_t;
#else
    #include <errno.h>
    #include <fcntl.h>           /* fcntl() */
    #include <netdb.h>           /* getaddrinfo() */
    #include <stdint.h>
    #include <unistd.h>
    #include <arpa/inet.h>       /* inet_XtoY() */
    #include <netinet/in.h>      /* IPPROTO_ICMP */
    #include <netinet/ip.h>
    #include <netinet/ip_icmp.h> /* struct icmp */
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <sys/types.h>
    typedef int socket_t;
#endif

#define IP_VERSION_ANY 0
#define IP_V4 4
#define IP_V6 6

#define MIN_IP_HEADER_SIZE 20
#define MAX_IP_HEADER_SIZE 60
#define MAX_IP6_PSEUDO_HEADER_SIZE 40

#ifndef ICMP_ECHO
    #define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHO6
    #define ICMP6_ECHO 128
#endif
#ifndef ICMP_ECHO_REPLY
    #define ICMP_ECHO_REPLY 0
#endif
#ifndef ICMP_ECHO_REPLY6
    #define ICMP6_ECHO_REPLY 129
#endif

#define REQUEST_TIMEOUT 1000000
#define REQUEST_INTERVAL 1000000

#ifdef _WIN32
    #define getpid _getpid
    #define usleep(usec) Sleep((usec) / 1000)
#endif

#pragma pack(push, 1)

#if defined _WIN32 || defined __CYGWIN__
    #ifdef _MSC_VER
        typedef unsigned __int8 uint8_t;
        typedef unsigned __int16 uint16_t;
        typedef unsigned __int32 uint32_t;
        typedef unsigned __int64 uint64_t;
    #endif
    struct icmp {
        uint8_t icmp_type;
        uint8_t icmp_code;
        uint16_t icmp_cksum;
        uint16_t icmp_id;
        uint16_t icmp_seq;
    };
#endif

struct ip6_pseudo_hdr {
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
    uint32_t ip6_plen;
    uint8_t ip6_zero[3];
    uint8_t ip6_nxt;
};

#pragma pack(pop)

/*
 * RFC 1071 - http://tools.ietf.org/html/rfc1071
 */
static uint16_t compute_checksum(const char *buf, size_t size) {
    size_t i;
    uint64_t sum = 0;

    for (i = 0; i < size; i += 2) {
        sum += *(uint16_t *)buf;
        buf += 2;
    }
    if (size - i > 0) {
        sum += *(uint8_t *)buf;
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

#ifdef _WIN32
    static void fprint_win32_error(FILE *stream,
                                   const char *callee,
                                   int error) {
        char *message = NULL;
        DWORD format_flags = FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS
            | FORMAT_MESSAGE_ALLOCATE_BUFFER
            | FORMAT_MESSAGE_MAX_WIDTH_MASK;
        DWORD result;

        result = FormatMessageA(
            format_flags,
            NULL,
            error,
            0,
            (char *)&message,
            0,
            NULL);
        if (result > 0) {
            fprintf(stream, "%s: %s\n", callee, message);
            LocalFree(message);
        } else {
            fprintf(stream, "%s: Unknown error\n", callee);
        }
    }
#endif

static void fprint_net_error(FILE *stream, const char *callee) {
#ifdef _WIN32
    fprint_win32_error(stream, callee, GetLastError());
#else
    fprintf(stream, "%s: %s\n", callee, strerror(errno));
#endif
}

static uint64_t get_time(void) {
#ifdef _WIN32
    LARGE_INTEGER count;
    LARGE_INTEGER frequency;
    if (QueryPerformanceCounter(&count) == 0
        || QueryPerformanceFrequency(&frequency) == 0) {
        return 0;
    }
    return count.QuadPart * 1000000 / frequency.QuadPart;
#else
    struct timeval now;
    return gettimeofday(&now, NULL) != 0
        ? 0
        : now.tv_sec * 1000000 + now.tv_usec;
#endif
}

int main(int argc, char **argv) {
#ifdef _WIN32
    int ws2_error;
    WSADATA ws2_data;
    u_long ioctl_value;
#endif
    char *target_host = NULL;
    int ip_version = IP_VERSION_ANY;
    int i;
    int gai_error;
    socket_t sockfd = -1;
    struct addrinfo addrinfo_hints;
    struct addrinfo *addrinfo_head = NULL;
    struct addrinfo *addrinfo = NULL;
    void *addr;
    char addrstr[INET6_ADDRSTRLEN] = "<unknown>";
    uint16_t id = (uint16_t)getpid();
    uint16_t seq;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-4") == 0) {
                ip_version = IP_V4;
            } else if (strcmp(argv[i], "-6") == 0) {
                ip_version = IP_V6;
            }
        } else {
            target_host = argv[i];
        }
    }

    if (target_host == NULL) {
        fprintf(stderr, "Usage: ping [-4] [-6] <target_host>\n");
        goto error_exit;
    }

#ifdef _WIN32
    ws2_error = WSAStartup(MAKEWORD(2, 2), &ws2_data);
    if (ws2_error != 0) {
        fprintf(stderr, "Failed to initialize WinSock2: %d\n", ws2_error);
        goto error_exit;
    }
#endif

    if (ip_version == IP_V4 || ip_version == IP_VERSION_ANY) {
        memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
        addrinfo_hints.ai_family = AF_INET;
        addrinfo_hints.ai_socktype = SOCK_RAW;
        addrinfo_hints.ai_protocol = IPPROTO_ICMP;
        gai_error = getaddrinfo(target_host,
                                NULL,
                                &addrinfo_hints,
                                &addrinfo_head);
    }

    if (ip_version == IP_V6
        || (ip_version == IP_VERSION_ANY && gai_error != 0)) {
        memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
        addrinfo_hints.ai_family = AF_INET6;
        addrinfo_hints.ai_socktype = SOCK_RAW;
        addrinfo_hints.ai_protocol = IPPROTO_ICMPV6;
        gai_error = getaddrinfo(target_host,
                                NULL,
                                &addrinfo_hints,
                                &addrinfo_head);
    }

    if (gai_error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_error));
        goto error_exit;
    }

    for (addrinfo = addrinfo_head;
         addrinfo != NULL;
         addrinfo = addrinfo->ai_next) {
        sockfd = socket(addrinfo->ai_family,
                        addrinfo->ai_socktype,
                        addrinfo->ai_protocol);
        if (sockfd >= 0) {
            break;
        }
    }

    if ((int)sockfd < 0) {
        fprint_net_error(stderr, "socket");
        goto error_exit;
    }

    switch (addrinfo->ai_family) {
        case AF_INET:
            addr = &((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr;
            break;
        case AF_INET6:
            addr = &((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr;
            break;
        default:
            abort();
    }

    inet_ntop(addrinfo->ai_family,
              addr,
              addrstr,
              sizeof(addrstr));

#ifdef _WIN32
    ioctl_value = 1;
    if (ioctlsocket(sockfd, FIONBIO, &ioctl_value) != 0) {
        fprint_net_error(stderr, "ioctlsocket");
        goto error_exit;
    }
#else
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        fprint_net_error(stderr, "fcntl");
        goto error_exit;
    }
#endif

    for (seq = 0; ; seq++) {
        struct icmp icmp_request = {0};
        int send_result;
        char recv_buf[MAX_IP_HEADER_SIZE + sizeof(struct icmp)];
        int recv_size;
        int recv_result;
        socklen_t addrlen;
        uint8_t ip_vhl;
        uint8_t ip_header_size;
        struct icmp *icmp_response;
        uint64_t start_time;
        uint64_t delay;
        uint16_t checksum;
        uint16_t expected_checksum;

        if (seq > 0) {
            usleep(REQUEST_INTERVAL);
        }

        icmp_request.icmp_type =
            addrinfo->ai_family == AF_INET6 ? ICMP6_ECHO : ICMP_ECHO;
        icmp_request.icmp_code = 0;
        icmp_request.icmp_cksum = 0;
        icmp_request.icmp_id = htons(id);
        icmp_request.icmp_seq = htons(seq);

        switch (addrinfo->ai_family) {
            case AF_INET:
                icmp_request.icmp_cksum =
                    compute_checksum((const char *)&icmp_request,
                                     sizeof(icmp_request));
                break;
            case AF_INET6: {
                /*
                 * Checksum is calculated from the ICMPv6 packet prepended
                 * with an IPv6 "pseudo-header" (this is different from IPv4).
                 *
                 * https://tools.ietf.org/html/rfc2463#section-2.3
                 * https://tools.ietf.org/html/rfc2460#section-8.1
                 */
                struct {
                    struct ip6_pseudo_hdr ip6_hdr;
                    struct icmp icmp;
                } data = {0};

                data.ip6_hdr.ip6_src.s6_addr[15] = 1; /* ::1 (loopback) */
                data.ip6_hdr.ip6_dst =
                    ((struct sockaddr_in6 *)&addrinfo->ai_addr)->sin6_addr;
                data.ip6_hdr.ip6_plen = htonl((uint32_t)sizeof(struct icmp));
                data.ip6_hdr.ip6_nxt = IPPROTO_ICMPV6;
                data.icmp = icmp_request;

                icmp_request.icmp_cksum =
                    compute_checksum((const char *)&data, sizeof(data));
                break;
            }
            default:
                abort();
        }

        send_result = sendto(sockfd,
                             (const char *)&icmp_request,
                             sizeof(icmp_request),
                             0,
                             addrinfo->ai_addr,
                             (int)addrinfo->ai_addrlen);
        if (send_result < 0) {
            fprint_net_error(stderr, "sendto");
            goto error_exit;
        }

        printf("Sent ICMP echo request to %s\n", addrstr);

        switch (addrinfo->ai_family) {
            case AF_INET:
                recv_size = (int)(MAX_IP_HEADER_SIZE + sizeof(struct icmp));
                break;
            case AF_INET6:
                /* When using IPv6 we don't receive IP headers in recvfrom. */
                recv_size = (int)sizeof(struct icmp);
                break;
            default:
                abort();
        }

        start_time = get_time();

        for (;;) {
            delay = get_time() - start_time;

            addrlen = (int)addrinfo->ai_addrlen;
            recv_result = recvfrom(sockfd,
                                   recv_buf,
                                   recv_size,
                                   0,
                                   addrinfo->ai_addr,
                                   &addrlen);
            if (recv_result == 0) {
                printf("Connection closed\n");
                break;
            }
            if (recv_result < 0) {
#ifdef _WIN32
                if (GetLastError() == WSAEWOULDBLOCK) {
#else
                if (errno == EAGAIN) {
#endif
                    if (delay > REQUEST_TIMEOUT) {
                        printf("Request timed out\n");
                        break;
                    } else {
                        /* No data available yet, try to receive again. */
                        continue;
                    }
                } else {
                    fprint_net_error(stderr, "recvfrom");
                    break;
                }
            }

            switch (addrinfo->ai_family) {
                case AF_INET:
                    /* In contrast to IPv6, for IPv4 connections we do receive
                     * IP headers in incoming datagrams.
                     *
                     * VHL = version (4 bits) + header length (lower 4 bits).
                     */
                    ip_vhl = *(uint8_t *)recv_buf;
                    ip_header_size = (ip_vhl & 0x0F) * 4;
                    break;
                case AF_INET6:
                    ip_header_size = 0;
                    break;
                default:
                    abort();
            }

            icmp_response = (struct icmp *)(recv_buf + ip_header_size);
            icmp_response->icmp_cksum = ntohs(icmp_response->icmp_cksum);
            icmp_response->icmp_id = ntohs(icmp_response->icmp_id);
            icmp_response->icmp_seq = ntohs(icmp_response->icmp_seq);

            if (icmp_response->icmp_id == id
                && ((addrinfo->ai_family == AF_INET
                        && icmp_response->icmp_type == ICMP_ECHO_REPLY)
                    ||
                    (addrinfo->ai_family == AF_INET6
                        && (icmp_response->icmp_type == ICMP6_ECHO
                            || icmp_response->icmp_type == ICMP6_ECHO_REPLY))
                )
            ) {
                break;
            }
        }

        if (recv_result <= 0) {
            continue;
        }

        checksum = icmp_response->icmp_cksum;
        icmp_response->icmp_cksum = 0;

        switch (addrinfo->ai_family) {
            case AF_INET:
                expected_checksum =
                    compute_checksum((const char *)icmp_response,
                                     sizeof(*icmp_response));
                break;
            case AF_INET6: {
                struct {
                    struct ip6_pseudo_hdr ip6_hdr;
                    struct icmp icmp;
                } data = {0};

                /* TODO: Need to get source and destination address somehow */
                /* data.ip6_hdr.ip6_src = ... */
                /* data.ip6_hdr.ip6_dst = ... */
                data.ip6_hdr.ip6_plen = htonl((uint32_t)sizeof(struct icmp));
                data.ip6_hdr.ip6_nxt = IPPROTO_ICMPV6;
                data.icmp = *icmp_response;

                expected_checksum =
                    compute_checksum((const char *)&data, sizeof(data));
                break;
            }
        }

        printf("Received ICMP echo reply from %s: seq=%d, time=%.3f ms",
               addrstr,
               icmp_response->icmp_seq,
               (double)delay / 1000.0);

        if (checksum != expected_checksum) {
            printf(" (incorrect checksum: %x != %x)\n",
                    checksum,
                    expected_checksum);
        } else {
            printf("\n");
        }
    }

    return EXIT_SUCCESS;

error_exit:
    if (addrinfo_head != NULL) {
        freeaddrinfo(addrinfo_head);
    }
    return EXIT_FAILURE;
}
