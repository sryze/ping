#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
    #include <process.h>         /* _getpid() */
    #include <winsock2.h>
    #include <ws2tcpip.h>        /* getaddrinfo() */
    #define getpid _getpid
#else
    #include <errno.h>
    #include <netdb.h>           /* getaddrinfo() */
    #include <stdint.h>
    #include <unistd.h>
    #include <arpa/inet.h>       /* inet_XtoY() */
    #include <netinet/in.h>      /* IPPROTO_ICMP */
    #include <netinet/ip_icmp.h> /* struct icmp */
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <sys/types.h>
#endif

#define MIN_IP_HEADER_SIZE 20
#define MAX_IP_HEADER_SIZE 60

#ifndef ICMP_ECHO
    #define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHO_REPLY
    #define ICMP_ECHO_REPLY 0
#endif

#define REQUEST_TIMEOUT  1000
#define REQUEST_INTERVAL 1000

#pragma pack(push, 1)

#if defined _WIN32 || defined __CYGWIN__
    #ifdef _MSC_VER
        typedef unsigned __int8 uint8_t;
        typedef unsigned __int16 uint16_t;
        typedef unsigned __int32 uint32_t;
        typedef unsigned __int64 uint64_t;
    #endif
    struct icmp {
        uint8_t  icmp_type;
        uint8_t  icmp_code;
        uint16_t icmp_cksum;
        uint16_t icmp_id;
        uint16_t icmp_seq;
    };
#endif

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
    static void fprint_win32_error(FILE *stream, int error) {
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
            fprintf(stream, "%s\n", message);
            LocalFree(message);
        } else {
            fprintf(stream, "Unknown error\n");
        }
    }
#endif

static void fprint_net_error(FILE *stream) {
#ifdef _WIN32
    fprint_win32_error(stream, GetLastError());
#else
    fprintf(stream, "%s\n", strerror(errno));
#endif
}

static void sleep_ms(int milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    usleep(milliseconds * 1000);
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
    DWORD timeout;
#else
    struct timeval timeout;
#endif
    char *hostname;
    int sockfd;
    int error;
    struct addrinfo addrinfo_hints;
    struct addrinfo *addrinfo_head;
    struct addrinfo *addrinfo;
    char addrstr[INET6_ADDRSTRLEN] = "<unknown>";
    uint16_t id = (uint16_t)getpid();
    uint16_t seq;

    if (argc < 2) {
        fprintf(stderr, "Usage: ping <destination>\n");
        exit(EXIT_FAILURE);
    }

#ifdef _WIN32
    ws2_error = WSAStartup(MAKEWORD(2, 2), &ws2_data);
    if (ws2_error != 0) {
        fprintf(stderr, "Failed to initialize WinSock2: %d\n", ws2_error);
        return FALSE;
    }
#endif

    hostname = argv[1];
    memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
    addrinfo_hints.ai_family = AF_INET;
    addrinfo_hints.ai_socktype = SOCK_RAW;
    addrinfo_hints.ai_protocol = IPPROTO_ICMP;

    error = getaddrinfo(hostname, NULL, &addrinfo_hints, &addrinfo_head);
    if (error != 0) {
        fprintf(stderr, "%s\n", gai_strerror(error));
        exit(EXIT_FAILURE);
    }

    for (addrinfo = addrinfo_head;
         addrinfo != NULL;
         addrinfo = addrinfo->ai_next) {
        sockfd = socket(addrinfo->ai_family,
                        addrinfo->ai_socktype,
                        addrinfo->ai_protocol);
        if (sockfd < 0) {
            fprint_net_error(stderr);
            continue;
        }

        /* Socket was successfully created. */
        break;
    }

    if (addrinfo == NULL) {
        fprintf(stderr, "%s\n", hostname);
        exit(EXIT_FAILURE);
    }

    switch (addrinfo->ai_family) {
        case AF_INET:
            inet_ntop(AF_INET,
                      &((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr,
                      addrstr,
                      sizeof(addrstr));
            break;
        case AF_INET6:
            inet_ntop(AF_INET6,
                      &((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr,
                      addrstr,
                      sizeof(addrstr));
            break;
    }

#ifdef _WIN32
    timeout = REQUEST_TIMEOUT;
#else
    timeout.tv_sec = REQUEST_TIMEOUT / 1000;
    timeout.tv_usec = (REQUEST_TIMEOUT % 1000) * 1000;
#endif

    if (setsockopt(sockfd,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   (const char *)&timeout,
                   sizeof(timeout)) < 0) {
        fprint_net_error(stderr);
        exit(EXIT_FAILURE);
    }
    if (setsockopt(sockfd,
                   SOL_SOCKET,
                   SO_SNDTIMEO,
                   (const char *)&timeout,
                   sizeof(timeout)) < 0) {
        fprint_net_error(stderr);
        exit(EXIT_FAILURE);
    }

    for (seq = 0; ; seq++) {
        struct icmp request;
        int send_result;
        char recv_buf[MAX_IP_HEADER_SIZE + sizeof(struct icmp)];
        int recv_result;
        socklen_t addrlen;
        uint8_t ip_vhl;
        uint8_t ip_header_size;
        struct icmp *reply;
        uint64_t start_time;
        uint64_t delay;
        uint16_t checksum;
        uint16_t expected_checksum;

        if (seq > 0) {
            sleep_ms(REQUEST_INTERVAL);
        }

        start_time = get_time();

        memset(&request, 0, sizeof(request));
        request.icmp_type = ICMP_ECHO;
        request.icmp_code = 0;
        request.icmp_cksum = 0;
        request.icmp_id = htons(id);
        request.icmp_seq = htons(seq);
        request.icmp_cksum =
            compute_checksum((const char *)&request, (int)sizeof(request));

        send_result = sendto(sockfd,
                             (const char *)&request,
                             sizeof(request),
                             0,
                             addrinfo->ai_addr,
                             addrinfo->ai_addrlen);
        if (send_result < 0) {
            fprint_net_error(stderr);
            exit(EXIT_FAILURE);
        }

        printf("Sent ICMP echo request to %s\n", addrstr);

        memset(&recv_buf, 0, sizeof(recv_buf));
        addrlen = addrinfo->ai_addrlen;
        recv_result = recvfrom(sockfd,
                               recv_buf,
                               MAX_IP_HEADER_SIZE + sizeof(struct icmp),
                               0,
                               addrinfo->ai_addr,
                               &addrlen);
        if (recv_result <= 0) {
#ifdef _WIN32
            if (GetLastError() == WSAETIMEDOUT) {
#else
            if (errno == ETIMEDOUT) {
#endif
                fprintf(stderr, "Request timed out\n");
            } else {
                fprint_net_error(stderr);
            }
            continue;
        }

        delay = get_time() - start_time;

        /* VHL = version + header length; each of them is 4 bits. */
        ip_vhl = *(uint8_t *)recv_buf;
        ip_header_size = (ip_vhl & 0x0F) * 4;

        reply = (struct icmp *)(recv_buf + ip_header_size);
        reply->icmp_cksum = ntohs(reply->icmp_cksum);
        reply->icmp_id = ntohs(reply->icmp_id);
        reply->icmp_seq = ntohs(reply->icmp_seq);

        if (reply->icmp_type != ICMP_ECHO_REPLY || reply->icmp_id != id) {
            continue;
        }

        checksum = reply->icmp_cksum;
        reply->icmp_cksum = 0;
        expected_checksum =
            compute_checksum((const char *)reply, (int)sizeof(*reply));

        printf("Received ICMP echo reply from %s: seq=%d, time=%.3f ms",
               addrstr,
               reply->icmp_seq,
               delay / 1000.0);

        if (checksum != expected_checksum) {
            printf(" (checksum mismatch: %x != %x)\n",
                    checksum,
                    expected_checksum);
        } else {
            printf("\n");
        }
    }
}
