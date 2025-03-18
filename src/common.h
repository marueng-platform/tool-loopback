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
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include "bitcalc.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <tuple>

#define ANSI_COLOR_WHITE "\x1B[37m"
#define ANSI_COLOR_RED "\x1B[31m"
#define ANSI_COLOR_GREEN "\x1B[32m"
#define ANSI_COLOR_YELLOW "\x1B[33m"
#define ANSI_COLOR_RESET "\x1B[0m"


#define YELLOW(fmt, ...) printf(ANSI_COLOR_YELLOW"" fmt ANSI_COLOR_RESET, ##__VA_ARGS__)
#define WHITE(fmt, ...) printf(ANSI_COLOR_WHITE"" fmt ANSI_COLOR_RESET, ##__VA_ARGS__)
#define RED(fmt, ...) printf(ANSI_COLOR_RED"" fmt ANSI_COLOR_RESET,  ##__VA_ARGS__)
#define GREEN(fmt, ...) printf(ANSI_COLOR_GREEN"" fmt ANSI_COLOR_RESET, ##__VA_ARGS__)


#define inaddrr(x) (*(struct in_addr *) &ifr->x[sizeof sa.sin_port])
#define IFRSIZE   ((int)(size * sizeof (struct ifreq)))

#define MAC_HEADER_LENGTH 14
#define IP_HEADER_LENGTH 20
#define UDP_HEADER_LENGTH 8
#define RTP_HEADER_LENGTH 12
#define MAC_IP_UDP_RTP_HEADER_LENGTH 54

#define MAC_IP_UDP_HEADER_LENGTH 42
#define PCAP_MAGIC_NUMBER 0xA1B2C3D4
#define PCAP_MAGIC_NUMBER_1 0xD4C3B2A1

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

typedef struct
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

typedef struct
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
    e_ARG_INPUT_FILTER,
    e_ARG_OUTPUT_FILTER,
    e_ARG_OUTPUT_FILE,
    e_ARG_MODE,
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
    e_MODE_PCAP_TO_FILE,
    e_MODE_DSTP_PCAP_TO_PCAP
}enum_MODE;
typedef struct {
    unsigned char version;
    unsigned char padding;
    unsigned char extension;
    unsigned char CSRC_Count;
    unsigned char Marker;
    unsigned char payload_Type;
    unsigned short SequenceNum;
    unsigned int Timestamp;
    unsigned int Packet_Offset;
} RtpHeader;

typedef struct {
    unsigned int dest_address;
    unsigned short port_number;
    unsigned short length;
    unsigned short group;
    unsigned char type;
    unsigned char random_access_point;
    unsigned char time_limit_flag;
    unsigned char signed_flag;
}DstpHeader;

int make_map();
double diff_time(timespec start);
std::vector<std::string> split(const std::string& s, char* seperator);
InOutParam parse_inout(std::string arg);
int get_addr(int sock, char * ifname, struct sockaddr * ifaddr);
std::list<Ethernet> GetNetworkInterface();
int parse_ip(const unsigned char* data, ip_header_t* ip);
int parse_udp(const unsigned char* data, udp_header_t *udp);
int parse_arg(int argc, char **argv, std::map<int, std::string>&args);
InOutParam parse_inout(std::string arg);
int help_print();
int ParseUdp(const unsigned char* data, udp_header_t *udp);
int ParseIp(const unsigned char* data, ip_header_t *ip);
int ParseDstp(unsigned char *pdata, DstpHeader *dstp);
int ParseRtp(unsigned char* pData, RtpHeader * rtp);
#endif //LOOPBACK_COMMON_H
