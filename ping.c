#include <errno.h>
#include <fcntl.h>
#include <netdb.h>            /* getaddrinfo() */
#include <netinet/in.h>       /* IPPROTO_ICMP */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>        /* inet_XtoY() */
#include <mach/clock_types.h> /* xSEC_PER_SEC macros */
#include <netinet/ip.h>       /* struct ip */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#define REQUEST_TIMEOUT 1000

#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_ECHO_REPLY   0

#define TIMEVAL_TO_MSEC(tv) ((double)(tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0))

#pragma pack(push, 1)

struct icmp {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

struct ip_icmp {
    struct ip ip;
    struct icmp icmp;
};

#pragma pack(pop)

/*
 * Computes the checksum of a packet as defined by RFC 1071:
 * http://tools.ietf.org/html/rfc1071
 */
uint16_t compute_checksum(void *buf, size_t size) {
    size_t i;
    uint64_t sum = 0;
    
    for (i = 0; i < size; i += 2) {
        /*  This is the inner loop */
        sum += *(uint16_t *)buf;
        buf = (uint8_t *)buf + 2;
    }
    
    /*  Add left-over byte, if any */
    if (size - i > 0) {
        sum += *(uint8_t *)buf;
    }
    
    /*  Fold 32-bit sum to 16 bits */
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    return (uint16_t)~sum;
}

int main(int argc, char **argv) {
    char *host;
    int sockfd;
    int error;
    struct addrinfo addrinfo_hints;
    struct addrinfo *addrinfo;
    struct addrinfo *addrinfo_cur;
    struct sockaddr_in sockaddr;
    struct timeval start_time;
    struct icmp request;
    struct ip_icmp reply;
    uint16_t id = (uint16_t)getpid();
    uint16_t seq = 0;
    ssize_t bytes_transferred;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: ping <host>\n");
        exit(EXIT_FAILURE);
    }
    
    host = argv[1];
    memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
    addrinfo_hints.ai_family = AF_INET;
    addrinfo_hints.ai_socktype = SOCK_RAW;
    addrinfo_hints.ai_protocol = IPPROTO_ICMP;
    
    error = getaddrinfo(host, NULL, &addrinfo_hints, &addrinfo);
    if (error != 0) {
        fprintf(stderr, "Error: getaddrinfo: %s\n", gai_strerror(error));
        exit(EXIT_FAILURE);
    }

    for (addrinfo_cur = addrinfo;
         addrinfo_cur != NULL;
         addrinfo_cur = addrinfo_cur->ai_next) {
        sockfd = socket(addrinfo_cur->ai_family,
                        addrinfo_cur->ai_socktype,
                        addrinfo_cur->ai_protocol);
        if (sockfd == -1) {
            fprintf(stderr, "Error: socket: %s\n", strerror(errno));
            continue;
        }
        
        /* Socket was successfully created. */
        break;
    }
    
    if (addrinfo_cur == NULL) {
        fprintf(stderr, "Error: Could not connect to %s\n", host);
        exit(EXIT_FAILURE);
    }
    
    memcpy(&sockaddr, addrinfo_cur->ai_addr, addrinfo_cur->ai_addrlen);
    freeaddrinfo(addrinfo);
    
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        fprintf(stderr, "Error: fcntl: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    for (seq = 0; ; seq++) {
        double delay = 0;
        
        memset(&request, 0, sizeof(request));
        request.type = ICMP_TYPE_ECHO_REQUEST;
        request.code = 0;
        request.checksum = 0;
        request.id = htons(id);
        request.seq = htons(seq);
        request.checksum = compute_checksum(&request, sizeof(request));
        
        bytes_transferred = sendto(sockfd,
                                   &request,
                                   sizeof(request),
                                   0,
                                   (struct sockaddr *)&sockaddr,
                                   sockaddr.sin_len);
        if (bytes_transferred < 0) {
            fprintf(stderr, "Error: sendto: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        
        printf("Sent ICMP echo request to %s\n", inet_ntoa(sockaddr.sin_addr));
        gettimeofday(&start_time, NULL);
        
        for (;;) {
            struct timeval cur_time;
            
            gettimeofday(&cur_time, NULL);
            delay = TIMEVAL_TO_MSEC(cur_time) - TIMEVAL_TO_MSEC(start_time);
            
            memset(&reply, 0, sizeof(reply));
            bytes_transferred = recvfrom(sockfd,
                                         &reply,
                                         sizeof(reply),
                                         0,
                                         NULL,
                                         NULL);
            if (bytes_transferred < 0) {
                if (errno != EAGAIN) {
                    fprintf(stderr, "Error: recvfrom: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                } else if (delay > REQUEST_TIMEOUT) {
                    printf("Timed out\n");
                    break;
                }
            } else {
                uint16_t checksum;
                uint16_t expected_checksum;
                
                checksum = reply.icmp.checksum;
                reply.icmp.checksum = 0;
                expected_checksum = compute_checksum(&reply.icmp, sizeof(reply.icmp));
                
                printf("Received ICMP echo reply from %s: seq=%d, time=%.3f ms",
                       inet_ntoa(sockaddr.sin_addr),
                       seq,
                       delay);
                
                if (checksum != expected_checksum) {
                    printf(" (checksum mismatch: %x != %x)\n", checksum, expected_checksum);
                } else {
                    printf("\n");
                }
                
                break;
            }
        }
        
        usleep(USEC_PER_SEC - delay * 1000);
    }
}
