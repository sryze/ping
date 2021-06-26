#ifndef _GNU_SOURCE
    #define _GNU_SOURCE /* for additional type definitions */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <process.h>  /* _getpid() */
#include <winsock2.h>
#include <ws2tcpip.h> /* getaddrinfo() */
#include <mswsock.h>  /* WSARecvMsg() */

#undef CMSG_SPACE
#define CMSG_SPACE WSA_CMSG_SPACE
#undef CMSG_FIRSTHDR
#define CMSG_FIRSTHDR WSA_CMSG_FIRSTHDR
#undef CMSG_NXTHDR
#define CMSG_NXTHDR WSA_CMSG_NXTHDR
#undef CMSG_DATA
#define CMSG_DATA WSA_CMSG_DATA

typedef SOCKET socket_t;
typedef WSAMSG msghdr_t;
typedef WSACMSGHDR cmsghdr_t;

/*
 * Pointer to the WSARecvMsg() function. It must be obtained at runtime...
 */
static LPFN_WSARECVMSG WSARecvMsg;

#else /* _WIN32 */

#ifdef __APPLE__
    #define __APPLE_USE_RFC_3542 /* for IPv6 definitions on Apple platforms */
#endif

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
typedef struct msghdr msghdr_t;
typedef struct cmsghdr cmsghdr_t;

#endif /* !_WIN32 */

#define IP_VERSION_ANY 0
#define IP_V4 4
#define IP_V6 6

#define ICMP_HEADER_LENGTH 8
#define MESSAGE_BUFFER_SIZE 1024

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
    #define socket(af, type, protocol) \
        WSASocketW(af, type, protocol, NULL, 0, 0)
    #define close_socket closesocket
    #define getpid _getpid
    #define usleep(usec) Sleep((DWORD)((usec) / 1000))
#else
    #define close_socket close
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

#endif /* _WIN32 || __CYGWIN__ */

struct ip6_pseudo_hdr {
    struct in6_addr src;
    struct in6_addr dst;
    uint8_t unused1[2];
    uint16_t plen;
    uint8_t unused2[3];
    uint8_t nxt;
};

struct icmp6_packet {
    struct ip6_pseudo_hdr ip6_hdr;
    struct icmp icmp;
};

#pragma pack(pop)

#ifdef _WIN32

static void psyserror(const char *s)
{
    char *message = NULL;
    DWORD format_flags = FORMAT_MESSAGE_FROM_SYSTEM
        | FORMAT_MESSAGE_IGNORE_INSERTS
        | FORMAT_MESSAGE_ALLOCATE_BUFFER
        | FORMAT_MESSAGE_MAX_WIDTH_MASK;
    DWORD result;

    result = FormatMessageA(format_flags,
                            NULL,
                            WSAGetLastError(),
                            0,
                            (char *)&message,
                            0,
                            NULL);
    if (result > 0) {
        fprintf(stderr, "%s: %s\n", s, message);
        LocalFree(message);
    } else {
        fprintf(stderr, "%s: Unknown error\n", s);
    }
}

#else /* _WIN32 */

#define psyserror perror

#endif /* !_WIN32 */

static uint64_t utime(void)
{
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

#ifdef _WIN32

static void init_winsock_lib(void)
{
    int error;
    WSADATA wsa_data;

    error = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (error != 0) {
        fprintf(stderr, "Failed to initialize WinSock: %d\n", error);
        exit(EXIT_FAILURE);
    }
}

static void init_winsock_extensions(int sockfd)
{
    int error;
    GUID recvmsg_id = WSAID_WSARECVMSG;
    DWORD size;

    /*
     * Obtain a pointer to the WSARecvMsg (recvmsg) function.
     */
    error = WSAIoctl(sockfd,
                     SIO_GET_EXTENSION_FUNCTION_POINTER,
                     &recvmsg_id,
                     sizeof(recvmsg_id),
                     &WSARecvMsg,
                     sizeof(WSARecvMsg),
                     &size,
                     NULL,
                     NULL);
    if (error == SOCKET_ERROR) {
        psyserror("WSAIoctl");
        exit(EXIT_FAILURE);
    }
}

#endif /* _WIN32 */

static uint16_t compute_checksum(const char *buf, size_t size)
{
    /* RFC 1071 - http://tools.ietf.org/html/rfc1071 */

    size_t i;
    uint64_t sum = 0;

    for (i = 0; i < size; i += 2) {
        sum += *(uint16_t *)buf;
        buf += 2;
    }
    if (size - i > 0)
        sum += *(uint8_t *)buf;

    while ((sum >> 16) != 0)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}

int main(int argc, char **argv)
{
    int i;
    char *hostname = NULL;
    int ip_version = IP_VERSION_ANY;
    int error;
    socket_t sockfd = -1;
    struct addrinfo *addrinfo_list;
    struct addrinfo *addrinfo;
    char dst_addr_str[INET6_ADDRSTRLEN] = "<unknown>";
    struct sockaddr_storage dst_addr;
    socklen_t dst_addr_len;
    uint16_t id = (uint16_t)getpid();
    uint16_t seq;
    uint64_t start_time;
    uint64_t delay;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-4") == 0) {
            ip_version = IP_V4;
        } else if (strcmp(argv[i], "-6") == 0) {
            ip_version = IP_V6;
        } else {
            hostname = argv[i];
        }
    }

    if (hostname == NULL) {
        fprintf(stderr, "Usage: ping [-4|-6] <hostname>\n");
        return EXIT_FAILURE;
    }

#ifdef _WIN32
    init_winsock_lib();
#endif

    if (ip_version == IP_V4 || ip_version == IP_VERSION_ANY) {
        struct addrinfo hints = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_RAW;
        hints.ai_protocol = IPPROTO_ICMP;
        error = getaddrinfo(hostname,
                            NULL,
                            &hints,
                            &addrinfo_list);
    }
    if (ip_version == IP_V6
        || (ip_version == IP_VERSION_ANY && error != 0)) {
        struct addrinfo hints = {0};
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_RAW;
        hints.ai_protocol = IPPROTO_ICMPV6;
        error = getaddrinfo(hostname,
                            NULL,
                            &hints,
                            &addrinfo_list);
    }
    if (error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return EXIT_FAILURE;
    }

    for (addrinfo = addrinfo_list;
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
        psyserror("socket");
        return EXIT_FAILURE;
    }

    memcpy(&dst_addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
    dst_addr_len = addrinfo->ai_addrlen;

    freeaddrinfo(addrinfo_list);
    addrinfo = NULL;
    addrinfo_list = NULL;

#ifdef _WIN32
    init_winsock_extensions(sockfd);
#endif

    /*
     * Switch the socket to non-blocking I/O mode. This allows us to implement
     * the timeout feature.
     */
#ifdef _WIN32
    {
        u_long opt_value = 1;
        if (ioctlsocket(sockfd, FIONBIO, &opt_value) != 0) {
            psyserror("ioctlsocket");
            return EXIT_FAILURE;
        }
    }
#else
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        psyserror("fcntl");
        return EXIT_FAILURE;
    }
#endif

    if (dst_addr.ss_family == AF_INET6) {
        /*
         * This allows us to receive IPv6 packet headers in incoming messages.
         */
        int opt_value = 1;
        error = setsockopt(sockfd,
                           IPPROTO_IPV6,
#ifdef _WIN32
                           IPV6_PKTINFO,
#else
                           IPV6_RECVPKTINFO,
#endif
                           (char *)&opt_value,
                           sizeof(opt_value));
        if (error != 0) {
            psyserror("setsockopt");
            return EXIT_FAILURE;
        }
    }

    /*
     * Convert the destination IP-address to a string.
     */
    inet_ntop(dst_addr.ss_family,
        dst_addr.ss_family == AF_INET6
            ? (void *)&((struct sockaddr_in6 *)&dst_addr)->sin6_addr
            : (void *)&((struct sockaddr_in *)&dst_addr)->sin_addr,
        dst_addr_str,
        sizeof(dst_addr_str));

    for (seq = 0; ; seq++) {
        struct icmp request;
        
        request.icmp_type =
            dst_addr.ss_family == AF_INET6 ? ICMP6_ECHO : ICMP_ECHO;
        request.icmp_code = 0;
        request.icmp_cksum = 0;
        request.icmp_id = htons(id);
        request.icmp_seq = htons(seq);

        if (dst_addr.ss_family == AF_INET6) {
            /*
             * Checksum is calculated from the ICMPv6 packet prepended
             * with an IPv6 "pseudo-header".
             *
             * https://tools.ietf.org/html/rfc2463#section-2.3
             * https://tools.ietf.org/html/rfc2460#section-8.1
             */
            struct icmp6_packet request_packet = {0};

            request_packet.ip6_hdr.src = in6addr_loopback;
            request_packet.ip6_hdr.dst =
                ((struct sockaddr_in6 *)&dst_addr)->sin6_addr;
            request_packet.ip6_hdr.plen = htons((uint16_t)ICMP_HEADER_LENGTH);
            request_packet.ip6_hdr.nxt = IPPROTO_ICMPV6;
            request_packet.icmp = request;

            request.icmp_cksum = compute_checksum((char *)&request_packet,
                                                  sizeof(request_packet));
        } else {
            request.icmp_cksum = compute_checksum((char *)&request,
                                                  sizeof(request));
        }

        error = (int)sendto(sockfd,
                            (char *)&request,
                            sizeof(request),
                            0,
                            (struct sockaddr *)&dst_addr,
                            dst_addr_len);
        if (error < 0) {
            psyserror("sendto");
            return EXIT_FAILURE;
        }

        printf("Sent ICMP echo request to %s\n", dst_addr_str);

        start_time = utime();

        for (;;) {
            char msg_buf[MESSAGE_BUFFER_SIZE];
            char packet_info_buf[MESSAGE_BUFFER_SIZE];
            struct in6_addr msg_addr = {0};
#ifdef _WIN32
            WSABUF msg_buf_struct = {
                sizeof(msg_buf),
                msg_buf
            };
            WSAMSG msg = {
                NULL,
                0,
                &msg_buf_struct,
                1,
                {sizeof(packet_info_buf), packet_info_buf},
                0
            };
            DWORD msg_len = 0;
#else
            struct iovec msg_buf_struct = {
                msg_buf,
                sizeof(msg_buf)
            };
            struct msghdr msg = {
                NULL,
                0,
                &msg_buf_struct,
                1,
                packet_info_buf,
                sizeof(packet_info_buf),
                0
            };
            size_t msg_len;
#endif
            cmsghdr_t *cmsg;
            size_t ip_hdr_len;
            struct icmp *reply;
            int reply_id;
            int reply_seq;
            uint16_t reply_checksum;
            uint16_t checksum;

#ifdef _WIN32
            error = WSARecvMsg(sockfd, &msg, &msg_len, NULL, NULL);
#else
            error = (int)recvmsg(sockfd, &msg, 0);
#endif

            delay = utime() - start_time;

            if (error < 0) {
#ifdef _WIN32
                if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
                if (errno == EAGAIN) {
#endif
                    if (delay > REQUEST_TIMEOUT) {
                        printf("Request timed out\n");
                        goto next;
                    } else {
                        /* No data available yet, try to receive again. */
                        continue;
                    }
                } else {
                    psyserror("recvmsg");
                    goto next;
                }
            }

#ifndef _WIN32
            msg_len = error;
#endif

            if (dst_addr.ss_family == AF_INET6) {
                /*
                 * The IP header is not included in the message, msg_buf points
                 * directly to the ICMP data.
                 */
                ip_hdr_len = 0;

                /*
                 * Extract the destination address from IPv6 packet info. This
                 * will be used to compute the checksum later.
                 */
                for (
                    cmsg = CMSG_FIRSTHDR(&msg);
                    cmsg != NULL;
                    cmsg = CMSG_NXTHDR(&msg, cmsg))
                {
                    if (cmsg->cmsg_level == IPPROTO_IPV6
                        && cmsg->cmsg_type == IPV6_PKTINFO) {
                        struct in6_pktinfo *pktinfo = (void *)CMSG_DATA(cmsg);
                        memcpy(&msg_addr,
                               &pktinfo->ipi6_addr,
                               sizeof(struct in6_addr));
                    }
                }
            } else {
                /*
                 * For IPv4, we must take the length of the IP header into
                 * account.
                 *
                 * Header length is stored in the lower 4 bits of the VHL field
                 * (VHL = Version + Header Length).
                 */
                ip_hdr_len = ((*(uint8_t *)msg_buf) & 0x0F) * 4;
            }

            reply = (struct icmp *)(msg_buf + ip_hdr_len);
            reply_id = ntohs(reply->icmp_id);
            reply_seq = ntohs(reply->icmp_seq);

            /*
             * Verify that this is indeed an echo reply packet.
             */
            if (!(dst_addr.ss_family == AF_INET
                  && reply->icmp_type == ICMP_ECHO_REPLY)
                && !(dst_addr.ss_family == AF_INET6
                    && reply->icmp_type == ICMP6_ECHO_REPLY)) {
                continue;
            }

            /*
             * Verify the ID and sequence number to make sure that the reply
             * is associated with the current request.
             */
            if (reply_id != id || reply_seq != seq) {
                continue;
            }

            reply_checksum = reply->icmp_cksum;
            reply->icmp_cksum = 0;

            /*
             * Verify the checksum.
             */
            if (dst_addr.ss_family == AF_INET6) {
                size_t size = sizeof(struct ip6_pseudo_hdr) + msg_len;
                struct icmp6_packet *reply_packet = calloc(1, size);

                if (reply_packet == NULL) {
                    psyserror("malloc");
                    return EXIT_FAILURE;
                }

                memcpy(&reply_packet->ip6_hdr.src,
                       &((struct sockaddr_in6 *)&dst_addr)->sin6_addr,
                       sizeof(struct in6_addr));
                reply_packet->ip6_hdr.dst = msg_addr;
                reply_packet->ip6_hdr.plen = htons((uint16_t)msg_len);
                reply_packet->ip6_hdr.nxt = IPPROTO_ICMPV6;
                memcpy(&reply_packet->icmp,
                       msg_buf + ip_hdr_len,
                       msg_len - ip_hdr_len);

                checksum = compute_checksum((char *)reply_packet, size);
            } else {
                checksum = compute_checksum(msg_buf + ip_hdr_len,
                                            msg_len - ip_hdr_len);
            }

            printf("Received ICMP echo reply from %s: seq=%d, time=%.3f ms%s\n",
                   dst_addr_str,
                   seq,
                   (double)delay / 1000.0,
                   reply_checksum != checksum ? " (bad checksum)" : "");
            break;
        }

next:
        if (delay < REQUEST_INTERVAL) {
            usleep(REQUEST_INTERVAL - delay);
        }
    }

    return EXIT_SUCCESS;
}
