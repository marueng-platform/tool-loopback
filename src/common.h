//
// Created by NamHee Cho on 2020/11/06.
//

#ifndef LOOPBACK_COMMON_H
#define LOOPBACK_COMMON_H

#include <iostream>
#include <vector>
#include <string>
#include <list>
#include <pcap.h>
#include <map>
#include <unistd.h>
#include <thread>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <tuple>


#define inaddrr(x) (*(struct in_addr *) &ifr->x[sizeof sa.sin_port])
#define IFRSIZE   ((int)(size * sizeof (struct ifreq)))



typedef struct {

    unsigned int magic_number; 	        /* magic number */
    unsigned short version_major;		/* major version number */
    unsigned short version_minor;		/* minor version number */
    int thiszone;		                /* GMT to local correction */
    unsigned int sigfigs;			    /* accuracy of timestamps */
    unsigned int snaplen;		        /* max length of captured packets, in octets */
    unsigned int network; 		        /* data link type */
} PcapHeader;

typedef struct {

    unsigned int ts_sec;                    /* timestamp seconds */
    unsigned int ts_usec;                 /* timestamp microseconds */
    unsigned int incl_len;                 /* number of octets of packet saved in file */
    unsigned int orig_len;                 /* actual length of packet*/
}  PcapPacketHeader;

typedef struct ip_header_s
{
    int header_length;
    int total_length;
    int checksum;
    int id;
    int fragment;
    int end_flag;
    int frag_offset;
    unsigned char protocol;
    unsigned long src;
    unsigned long dest;
    unsigned char version;
} ip_header_t;

typedef struct udp_header_s
{
    unsigned short src_port;
    unsigned short dest_port;
    unsigned short length;
    unsigned short checksum;
} udp_header_t;

typedef enum{
    e_ARG_EXCEPT = -1,
    e_ARG_VERSION = 0,
    e_ARG_HELP = 1,
    e_ARG_INPUT_NIC,
    e_ARG_INPUT_PCAP,
    e_ARG_OUTPUT_NIC,
    e_ARG_INPUT_UDP,
    e_ARG_OUTPUT_UDP,
    e_ARG_OK,
}enum_ARG;

typedef struct {
    char interface[32];
    char mac[32];
    char address[32];
    char netmask[32];
} Ethernet;

typedef struct {
    std::string udp;
    std::string adapter;
}InOutParam;

typedef enum {
    e_MODE_BYPASS = 0,
    e_MODE_UDP_TO_UDP,
    e_MODE_FILE_TO_UDP,
}enum_MODE;

int make_map();
double diff_time(timespec start);
std::vector<std::string> split(const std::string& s, char* seperator);
InOutParam parse_inout(std::string arg);
int get_addr(int sock, char * ifname, struct sockaddr * ifaddr);
std::list<Ethernet> GetNetworkInterface();
int parse_ip(const unsigned char* data, ip_header_t* ip);
int parse_udp(const unsigned char* data, udp_header_t *udp);
int parse_arg(int argc, void **argv, std::map<int, std::string>&args);

#endif //LOOPBACK_COMMON_H
