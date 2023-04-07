//
// Created by NamHee Cho on 2020/11/06.
//
#include <cstring>
#include "common.h"

std::map<std::string, int>k_arg_map;

int make_map() {
    k_arg_map["--version"] = e_ARG_VERSION;
    k_arg_map["--help"] = e_ARG_HELP;
    k_arg_map["-i"] = e_ARG_INPUT_NIC;
    k_arg_map["-pcap"] = e_ARG_INPUT_PCAP;
    k_arg_map["-o"] = e_ARG_OUTPUT_NIC;
    k_arg_map["-input"] = e_ARG_INPUT_UDP;
    k_arg_map["-output"] = e_ARG_OUTPUT_UDP;
    k_arg_map["-filter"] = e_ARG_INPUT_FILTER;
    return 0;
}

int help_print(){
    GREEN("ex) Multicast to Unicast\n");
    printf("./loopback -input udp://{Receive Multicast}?adapter={Receiver ip} -output udp://{Unicast address}?adapter={Sender ip}\n");
    printf("./loopback -input udp://239.0.0.3:30000?adapter=192.168.1.156 -output udp://10.7.23.33:8888?adapter=127.0.0.1\n");
    GREEN("\nex) Network Loopback\n");
    printf("./loopback -i {Receiver NIC} -o {Sender NIC}\n");
    printf("./loopback -i eno1 -o lo\n");
    GREEN("\nex)Pcap Sender Mode 1\n");
    printf("./loopback -pcap {PCAP path} -o {Sender NIC}\n");
    printf("./loopback -pcap /root/sample.pcap -o eth1\n");
    GREEN("\nex)Pcap Sender Mode 2\n");
    printf("./loopback -pcap {PCAP path} -filter udp://{Multicast Address} -o {Sender NIC}\n");
    printf("./loopback -pcap /root/sample.pcap -filter udp://239.0.0.3:34000 -o eth1\n");
    GREEN("\nex)Pcap Sender Mode 3\n");
    printf("./loopback -pcap {PCAP path} -filter udp://{Multicast Filter Address} -o {Receiver NIC} -output udp://{Output Multicast Address}\n");
    printf("./loopback -pcap /root/sample.pcap -filter udp://239.0.0.3:34000 -o eth1 -output udp://239.0.0.3:30000\n");
    return 0;
}

int parse_arg(int argc, char **argv, std::map<int, std::string>&args){
    int i;
    bool input = false;
    bool output = false;
    for(i=1; i<argc; i++){
        std::string value;
        std::string str = (char*)argv[i];
        if(str.find("--version") == 0){
            std::cout << str << std::endl;
        }else if(str.find("--help") == 0) {
            std::cout << str << std::endl;
        }else if(str.find("-i") == 0){
            input = true;
        }else if(str.find("-o") == 0) {
            output = true;
        }
        auto f_i = k_arg_map.find(str);
        if(f_i == k_arg_map.end()){
            return e_ARG_EXCEPT;
        }

        i++;
        str = (char*)argv[i];
        args[f_i->second] = str;

        if(f_i->second == e_ARG_INPUT_UDP){
            parse_inout(str);
        }
        if(f_i->second == e_ARG_OUTPUT_UDP){
            parse_inout(str);
        }
    }
    if(input == true && output == true) {
    }
    return e_ARG_OK;
}

InOutParam parse_inout(std::string arg)
{
    InOutParam inout;
    auto items = split(arg,(char*)"?");
    int size = items.size();

    auto udp_f = [](std::string s) -> std::tuple<bool, std::string>{
        std::string val;
        bool find = false;
        int head = s.find("udp://");
        if(head == 0){
            val = s.substr(6, s.size() - 6);
            find = true;
        }
        return std::make_tuple(find, val);
    };

    if(size == 2){
        auto p = split(items[1], (char*)"&");
        for(auto it: p){
            if(it.find("adapter") == 0){
                auto dict = split(it, (char*)"=");
                if(dict.size() == 2){
                    inout.adapter = dict[1];
                }
            }
        }
    }
    if(items[0].find("udp://") == 0){
        auto r = udp_f(items[0]);
        if(std::get<0>(r)){
            inout.udp = std::get<1>(r);
        }
    }
//    printf("%s, %s\n", inout.udp.c_str(), inout.adapter.c_str());
    return inout;
}


double diff_time(timespec start)
{
    timespec stop = {0,};
    timespec result = {0,};
    double fTime = 0;
    clock_gettime(CLOCK_MONOTONIC, &stop);

    if ((stop.tv_nsec - start.tv_nsec) < 0) {
        result.tv_sec = stop.tv_sec - start.tv_sec - 1;
        result.tv_nsec = stop.tv_nsec - start.tv_nsec + 1000000000;
    }
    else {
        result.tv_sec = stop.tv_sec - start.tv_sec;
        result.tv_nsec = stop.tv_nsec - start.tv_nsec;
    }
    fTime = result.tv_sec;
    fTime += ((double)result.tv_nsec / 1000000000.0);
    return fTime;
}

std::vector<std::string> split(const std::string& s, char* seperator)
{
    std::vector<std::string> output;
    std::string::size_type prev_pos = 0, pos = 0;
    while ((pos = s.find(seperator, pos)) != std::string::npos) {
        std::string substring(s.substr(prev_pos, pos - prev_pos));
        output.push_back(substring);
        prev_pos = ++pos;
    }
    output.push_back(s.substr(prev_pos, pos - prev_pos));
    return output;
}

int parse_udp(const unsigned char* data, udp_header_t *udp)
{

    udp->src_port = htons(*((unsigned short*)& data[0]));
    udp->dest_port = htons(*((unsigned short*)& data[2]));
    udp->length = htons(*((unsigned short*)& data[4]));
    udp->checksum = htons(*((unsigned short*)& data[6]));
    return 8;
}
int parse_ip(const unsigned char* data, ip_header_t* ip)
{
    ip->header_length = ((int)(data[0] & 0x0F) * 4);
    ip->total_length = (int)data[2] * 256 + (int)data[3];
    ip->fragment = (data[6] >> 6) & 0x01;
    ip->end_flag = (data[6] >> 5) & 0x01;
    ip->frag_offset = ((int)(data[6] & 0x1F) * 256 + (int)data[7]) * 8;
    ip->protocol = (unsigned char)data[9];
    ip->src = htonl(*((unsigned long*)& data[12]));
    ip->dest = htonl(*((unsigned long*)& data[16]));
    ip->checksum = (int)data[10] * 256 + (int)data[11];
    ip->id = (int)data[4] * 256 + (int)data[5];
    return 20;
}

std::list<Ethernet> GetNetworkInterface()
{
    std::list<Ethernet> eth_list;
    unsigned char      *u;
    int                sockfd, size = 1;
    struct ifreq       *ifr;
    struct ifconf      ifc;
    struct sockaddr_in sa;

    if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))) {
        fprintf(stderr, "Cannot open socket.\n");
        exit(EXIT_FAILURE);
    }
    ifc.ifc_len = IFRSIZE;
    ifc.ifc_req = NULL;

    do {
        ++size;
        // realloc buffer size until no overflow occurs
        if (NULL == (ifc.ifc_req = (ifreq *)realloc(ifc.ifc_req, IFRSIZE)))
        {
            fprintf(stderr, "Out of memory.\n");
            exit(EXIT_FAILURE);
        }
        ifc.ifc_len = IFRSIZE;
        if (ioctl(sockfd, SIOCGIFCONF, &ifc)) {
            perror("ioctl SIOCFIFCONF");
            exit(EXIT_FAILURE);
        }
    } while (IFRSIZE <= ifc.ifc_len);
    struct sockaddr ifa;
    get_addr(sockfd, (char*)"ppp0", &ifa);
    int cnt = 0;;
    ifr = ifc.ifc_req;

    for (; (char *)ifr < (char *)ifc.ifc_req + ifc.ifc_len; ++ifr) {
        Ethernet eth;
        if (ifr->ifr_addr.sa_data == (ifr + 1)->ifr_addr.sa_data) {
            continue;  // duplicate, skip it
        }
        if (ioctl(sockfd, SIOCGIFFLAGS, ifr)) {
            continue;  // failed to get flags, skip it
        }
        strcpy(eth.interface, ifr->ifr_name);
        strcpy(eth.address, inet_ntoa(inaddrr(ifr_addr.sa_data)));
        if (0 == ioctl(sockfd, SIOCGIFHWADDR, ifr)) {
            switch (ifr->ifr_hwaddr.sa_family) {
                default:
                    continue;
                case  ARPHRD_NETROM:  case  ARPHRD_ETHER:  case  ARPHRD_PPP:
                case  ARPHRD_EETHER:  case  ARPHRD_IEEE802: break;
            }
            u = (unsigned char *)&ifr->ifr_addr.sa_data;
            sprintf(eth.mac, "%2.2x.%2.2x.%2.2x.%2.2x.%2.2x.%2.2x", u[0], u[1], u[2], u[3], u[4], u[5]);
        }
        if (0 == ioctl(sockfd, SIOCGIFNETMASK, ifr) &&
            strcmp("255.255.255.255", inet_ntoa(inaddrr(ifr_addr.sa_data)))) {
        }
        strcpy(eth.netmask, inet_ntoa(inaddrr(ifr_addr.sa_data)));
        eth_list.push_back(eth);
        cnt++;
    }
    close(sockfd);
    return eth_list;
}

int get_addr(int sock, char * ifname, struct sockaddr * ifaddr)
{
    struct ifreq *ifr;
    struct ifreq ifrr;
    struct sockaddr_in sa;
    ifr = &ifrr;
    ifrr.ifr_addr.sa_family = AF_INET;
    strncpy(ifrr.ifr_name, ifname, sizeof(ifrr.ifr_name));
    if (ioctl(sock, SIOCGIFADDR, ifr) < 0) {
        return -1;
    }
    *ifaddr = ifrr.ifr_addr;
    printf("Address for %s: %s\n", ifname, inet_ntoa(inaddrr(ifr_addr.sa_data)));
    return 0;
}