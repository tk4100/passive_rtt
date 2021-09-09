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

// table size
#define RTT_TABLE_SIZE 64

//----------------------------------------------

struct rtt_measure
	{
	uint32_t tsval;

	uint64_t rtt_us;

	uint16_t sport_out;
	uint16_t dport_out;

	uint16_t sport_in;
	uint16_t dport_in;

	struct timespec out_time;
	struct timespec in_time;
	};


//----------------------------------------------

struct rtt_measure rtt_table[RTT_TABLE_SIZE];
uint32_t rtt_table_cursor;




int32_t findTSVal(uint32_t TSVal)
	{
	uint32_t i = 0;
	while(i<RTT_TABLE_SIZE)
		{
		if(rtt_table[i].tsval == TSVal)
			return(i);
		i++;
		}
	return(-1);
	}

void completeRTT(uint32_t TSVal, struct timespec *now, uint16_t sport, uint16_t dport)
	{
	uint32_t i = 0;
	uint64_t outtime = 0;
	uint64_t intime = 0;

	while(i<RTT_TABLE_SIZE)
		{
		if(rtt_table[i].tsval == TSVal)
			{
			rtt_table[i].in_time.tv_sec = now->tv_sec;
			rtt_table[i].in_time.tv_nsec = now->tv_nsec;

			rtt_table[i].sport_in = sport;
			rtt_table[i].dport_in = dport;

			outtime = (rtt_table[i].out_time.tv_sec * 1000 * 1000) + (rtt_table[i].out_time.tv_nsec / 1000);
			intime = (now->tv_sec * 1000 * 1000) + (now->tv_nsec / 1000);

			rtt_table[i].rtt_us = intime - outtime;
			}
		i++;
		}
	}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
	{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	const struct ether_header *ethernet;
	const struct ip *ip;
	const struct tcphdr *tcp;
	const char *payload;

	int size_ip;
	int size_tcp;
	int size_payload;
	
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
				int32_t val_index = -1;
				int32_t ecr_index = -1;
				uint32_t *TSVal;
				uint32_t *TSecr;

				TSVal = (uint32_t*)(kind + 2);
				TSecr = (uint32_t*)(kind + 2 + 4);

				val_index = findTSVal(*TSVal);
				if(val_index == -1)
					{
					rtt_table[rtt_table_cursor].tsval = *TSVal;
					rtt_table[rtt_table_cursor].out_time.tv_sec = now.tv_sec;
					rtt_table[rtt_table_cursor].out_time.tv_nsec = now.tv_nsec;

					rtt_table[rtt_table_cursor].sport_out = tcp->th_sport;
					rtt_table[rtt_table_cursor].dport_out = tcp->th_dport;

					if(rtt_table_cursor < RTT_TABLE_SIZE - 1)
						rtt_table_cursor++;
					else
						rtt_table_cursor = 0;
					}
				else
					{
					rtt_table[val_index].out_time.tv_sec = now.tv_sec;
					rtt_table[val_index].out_time.tv_nsec = now.tv_nsec;
					}
					

				ecr_index = findTSVal(*TSecr);
				//printf("ECR Index: %d\n", ecr_index);
				if(ecr_index > -1)
					completeRTT(*TSecr, &now, tcp->th_sport, tcp->th_dport);
					

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

	// clear out our table of things, and reset our cursor
	memset(&rtt_table, 0, sizeof(rtt_table));
	rtt_table_cursor = 0;

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 100;			/* number of packets to capture */

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
	while(1)
		{
		pcap_loop(handle, num_packets, got_packet, NULL);

		for(int i=0;i<RTT_TABLE_SIZE;i++)
			printf("TSVal: %u, Time out: %ld.%.9ld, Time in: %ld.%.9ld, Out Ports: %d:%d, In Ports: %d:%d RTT uS: %lu\n", rtt_table[i].tsval, rtt_table[i].out_time.tv_sec, rtt_table[i].out_time.tv_nsec, rtt_table[i].in_time.tv_sec, rtt_table[i].in_time.tv_nsec, rtt_table[i].sport_out, rtt_table[i].dport_out, rtt_table[i].sport_in, rtt_table[i].dport_in, rtt_table[i].rtt_us);
		printf("\n");
		}

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}


