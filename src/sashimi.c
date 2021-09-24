include "sashimi.h"

#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>



#define BUFFSIZE 	65536
//#define TCP			6

int raw_tcp()
{
	int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	
	if (-1 == sock_fd)
	{
		perror("failed to create raw TCP socket");
		_exit(EXIT_FAILURE);
	}

	return sock_fd; 
}

void print_packet(uint8_t * packet, ssize_t size)
{
	struct iphdr *iph = (struct iphdr *)packet;
	if (TCP == iph->protocol)
	{
		fprintf(stdout, "This is totally a TCP packet (%ld).\n", size);
	}
	else
	{
		fprintf(stdout, "That was not TCP (%ld).\n", size);
	}
	
}

int dummy(void)
{
	return 1;
}

/* Driver to test the library */
int main(int argc, char ** argv)
{
	fprintf(stdout, "%s (%d args) can sniff raw packets...\n\n", argv[0], argc);	

	struct sockaddr saddr;
	socklen_t saddr_size = sizeof(saddr);
	ssize_t bytes = 0;
	uint8_t * buffer = calloc(BUFFSIZE, sizeof(uint8_t));
	int my_raw = raw_tcp();

	for (int i = 0; i < 3; i++)
	{
		bytes = recvfrom(my_raw, buffer, BUFFSIZE, 0, &saddr, &saddr_size);
		fprintf(stdout, "%d: ", i);
		print_packet(buffer, bytes);
	}

	return EXIT_SUCCESS;
}

/* References:
 * 
 * binarytides.com/packet-sniffer-code-c-linux/
 *
 * binarytides.com/whateverthesecondoneis...
 *
 */
