#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// IP 헤더 구조체
struct ip_header {
    u_char ip_vhl;          // 버전 + 헤더 길이
    u_char ip_tos;          // 서비스 타입
    u_short ip_len;         // 전체 길이
    u_short ip_id;          // Identification
    u_short ip_off;         // Fragment offset
    u_char ip_ttl;          // Time to Live
    u_char ip_p;            // 프로토콜
    u_short ip_sum;         // Checksum
    struct in_addr ip_src;  // 출발지 주소
    struct in_addr ip_dst;  // 목적지 주소
};

// TCP 헤더 구조체
struct tcp_header {
    u_short th_sport;       // 출발지 포트
    u_short th_dport;       // 목적지 포트
    u_int th_seq;          // Sequence number
    u_int th_ack;          // Acknowledgement number
    u_char th_offx2;       // Data offset
    u_char th_flags;       // Flags
    u_short th_win;        // Window
    u_short th_sum;        // Checksum
    u_short th_urp;        // Urgent pointer
};

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

char* target_host;

static int check_http_host(unsigned char* data, int size) {
    char* http_data = (char*)data;
    char* host_field = strstr(http_data, "Host: ");

    if (host_field) {
        char host[256] = {0,};
        sscanf(host_field + 6, "%255[^\r\n]", host);

        char* newline = strchr(host, '\r');
        if (newline) *newline = '\0';
        newline = strchr(host, '\n');
        if (newline) *newline = '\0';

        printf("Found Host: %s\n", host);

        if (strcasecmp(host, target_host) == 0) {
            printf("Matched target host! Dropping packet.\n");
            return 1;
        }
    }
    return 0;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
    int blocked = 0;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
		printf("payload_len=%d\n", ret);
        dump(data, ret);

        struct ip_header *iph = (struct ip_header *)data;

        int ip_header_len = (iph->ip_vhl & 0x0f) * 4;

        if (iph->ip_p == 6) {
            struct tcp_header *tcph = (struct tcp_header *)(data + ip_header_len);

            int tcp_header_len = ((tcph->th_offx2 & 0xf0) >> 4) * 4;

            if (ntohs(tcph->th_dport) == 80) {
                unsigned char *http_data = data + ip_header_len + tcp_header_len;
                int http_length = ret - ip_header_len - tcp_header_len;

                if (http_length > 0 &&
                    (strncmp((char*)http_data, "GET ", 4) == 0 ||
                     strncmp((char*)http_data, "POST ", 5) == 0)) {
                    blocked = check_http_host(http_data, http_length);
                }
            }
        }
    }

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);
    int blocked = 0;

    unsigned char *payload_data;
    int payload_len = nfq_get_payload(nfa, &payload_data);
    if (payload_len >= 0) {
        struct ip_header *iph = (struct ip_header *)payload_data;
        if (iph->ip_p == 6) { // TCP
            int ip_header_len = (iph->ip_vhl & 0x0f) * 4;
            struct tcp_header *tcph = (struct tcp_header *)(payload_data + ip_header_len);
            if (ntohs(tcph->th_dport) == 80) {
                int tcp_header_len = ((tcph->th_offx2 & 0xf0) >> 4) * 4;
                unsigned char *http_data = payload_data + ip_header_len + tcp_header_len;
                int http_length = payload_len - ip_header_len - tcp_header_len;
                blocked = check_http_host(http_data, http_length);
            }
        }
    }

    return nfq_set_verdict(qh, id, blocked ? NF_DROP : NF_ACCEPT, 0, NULL);
}
int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: %s <host_to_block>\n", argv[0]);
        exit(1);
    }

    target_host = argv[1];
    printf("Blocking traffic to host: %s\n", target_host);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
        }

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

