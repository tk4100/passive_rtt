#include <unistd.h>
#include <sys/stat.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

//----------------------------------------------

struct tcpConnection
	{
	uint32_t tstamp;


	uint32_t src;
	uint32_t dst;

	uint16_t sport;
	uint16_t dport;
	};

//----------------------------------------------

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
	{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct ether_header *ethernet;  /* The ethernet header [1] */
	const struct ip *ip;              /* The IP header */
	const struct tcphdr *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	//printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct ether_header*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct ip*)(packet + SIZE_ETHERNET);
	size_ip = ip->ip_hl*4;
	if (size_ip < 20) {
		return;
	}

	if(ip->ip_p == IPPROTO_TCP)
		{
		//printf("   Protocol: TCP\n");
		/* define/compute tcp header offset */
		tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = tcp->th_off*4;

		if (size_tcp < 20) return;

		if (size_tcp > 24)
			{
			uint8_t *kind;
			uint8_t *len;

			// yes we're skipping any packets that don't have their *first* option
			// set to timestamps.  whatever, we're going for an average value
			// and there is plenty of traffic to sample.
			kind = (uint8_t*)(packet + SIZE_ETHERNET + size_ip + sizeof(struct tcphdr));

			while(*kind == TCPOPT_NOP)
				kind += TCPOLEN_NOP;
			if(*kind == TCPOPT_TIMESTAMP)
				{
				uint32_t *TSVal;
				uint32_t *TSecr;

				TSVal = (uint32_t*)(kind + 2);
				TSecr = (uint32_t*)(kind + 2 + 4);

				printf("%d->%d, TSVal: %u, TSecr: %u\n", tcp->th_sport, tcp->th_dport, *TSVal, *TSecr);
				// so now we need to keep a table of current timestamps for local senders, and compare
				// incoming TSecrs against it.
				}
			}
		}

	/* Graphite stuff
	if(last_time  != now.tv_sec)
		{
		//printf("Tick! %d -> %d\n", last_time, now.tv_sec);
		char path[4096];
		for(int i = 0;i<65536;i++)
			{
			if(bytes_per_port[i] == 0)
				continue;
			snprintf(path, 4096, "portstats.colo.fw.%d", i);
			graphite_send_plain(path, bytes_per_port[i], last_time);
			}
		memset(bytes_per_port, 0, sizeof(unsigned long)*65536);
		last_time = now.tv_sec;
		}
	*/
	
	return;
	}

int main(int argc, char **argv)
	{

	/*
	//daemonize!!
        pid_t pid;
        pid = fork();

        //exit with the fork status
        if(pid < 0)
                exit(127);
        if(pid > 0)
                exit(0);
        // Child past here
        //clean up
        umask(0);
        setsid();
        chdir("/");
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        /// Daemonized!
	*/

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 40;			/* number of packets to capture */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}


	
	
	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	//char host[] = "173.255.243.159";
	//graphite_init(host, 2003);

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}


