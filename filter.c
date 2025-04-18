#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <pcap.h>

/*
 * Convert little endian integers to host endianness.
 */
long long int letoh(const unsigned char *bytes, int size) {
	long long int ret;

	ret = 0;
	while (--size >= 0) {
		ret <<= CHAR_BIT;
		ret |= bytes[size];
	}
	return ret;
}

/*
 * Print an IEX-TP timestamp in RFC 3339 format. See IEX Transport
 * specification.
 *
 * NOTE: Parsing RFC 3339 format in C is challenging; however, this choice was
 * made to be able to express nanosecond precision.
 */
void puttimestamp(long long int ts) {
	time_t clock;
	struct tm *tm;

	clock = ts / 1000000000;
	tm = gmtime((const time_t *)&clock);
	printf("%04d-%02d-%02d", tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday);
	printf("T%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
	printf(".%09lld", ts%1000000000);
	printf("%+03ld:%02ld", tm->tm_gmtoff/60/60, labs(tm->tm_gmtoff/60%60));
}

/*
 * Process an IEX-TP message. See IEX TOPS specification at
 * <https://storage.googleapis.com/assets-bucket/exchange/assets/IEX%20TOPS%20Specification%20v1.66.pdf>.
 */
void process_iex_message(const u_char *bytes) {
	int i;

	putchar(bytes[0]);
	switch (bytes[0]) {
	case 'Q':
		printf(",0x%02x,", bytes[1]);
		puttimestamp(letoh(bytes+2, 8));
		putchar(',');
		for (i = 0; (bytes+10)[i] != ' ' && i < 8; ++i)
			putchar((bytes+10)[i]);
		printf(",%lu", (long unsigned int)letoh(bytes+18, 4));
		printf(",%.4f", letoh(bytes+22, 8)/1e4);
		printf(",%.4f", letoh(bytes+30, 8)/1e4);
		printf(",%lu", (long unsigned int)letoh(bytes+38, 4));
		break;
	case 'S':
		printf(",%c,", bytes[1]);
		puttimestamp(letoh(bytes+2, 8));
		break;
	case 'T':
		printf(",0x%02x,", bytes[1]);
		puttimestamp(letoh(bytes+2, 8));
		putchar(',');
		for (i = 0; (bytes+10)[i] != ' ' && i < 8; ++i)
			putchar((bytes+10)[i]);
		printf(",%lu", (long unsigned int)letoh(bytes+18, 4));
		printf(",%.4f", letoh(bytes+22, 8)/1e4);
		break;
	}
	putchar('\n');
}

/*
 * Process an IEX-TP segment. See IEX Transport specification at
 * <https://storage.googleapis.com/assets-bucket/exchange/assets/IEX_Transport_Specification.pdf>.
 */
#define IEX_HDR_LEN 40
void process_iex_segment(const u_char *bytes) {
	unsigned int message_count, message_length;

	/*
	 * IEX-TP message count field is at offset 14 in the header and has
	 * width 2.
	 */
	message_count = letoh(bytes+14, 2);
	bytes += IEX_HDR_LEN;
	while (message_count-- > 0) {
		message_length = letoh(bytes, 2);
		bytes += 2;
		if (message_length > 0) process_iex_message(bytes);
		bytes += message_length;
	}
}

void process_udp(const u_char *bytes) {
	process_iex_segment(bytes + sizeof(struct udphdr));
}

void process_ip(const u_char *bytes) {
	assert(((struct ip *)bytes)->ip_p == IPPROTO_UDP);
	/* IP header length is stored in units of 32-bit words. */
	process_udp(bytes + ((struct ip *)bytes)->ip_hl * 4);
}

void process_ethernet(
    u_char *user,
    const struct pcap_pkthdr *h,
    const u_char *bytes) {
	assert(ntohs(((struct ether_header *)bytes)->ether_type)
	    == ETHERTYPE_IP);
	process_ip(bytes + ETHER_HDR_LEN);
}

int main(void) {
	pcap_t *p;
	char errbuf[PCAP_ERRBUF_SIZE];

	p = pcap_fopen_offline(stdin, errbuf);
	assert(pcap_datalink(p) == DLT_EN10MB);
	pcap_loop(p, -1, process_ethernet, NULL);
	return 0;
}
