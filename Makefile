all:
	clang -o rtt -lpcap rtt.c graphite-client.c
