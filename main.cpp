#include <cstring>
#include "main.h"

int main(int argc, void** argv)
{
    int mode = 0;
    auto eth = GetNetworkInterface();
    for(auto it: eth){
        printf("%s, %s\n", it.interface, it.address);
    }
    std::thread *th = NULL;
    std::map<int, std::string> args;
    make_map();
    int rs = parse_arg(argc,argv, args);
    switch (rs){
        case e_ARG_VERSION:
        case e_ARG_HELP:
        case e_ARG_EXCEPT:
            printf("return\n");
            return 0;
        default:
            break;
    }

    if(args.find(e_ARG_INPUT_PCAP) != args.end()){
        mode = e_MODE_FILE_TO_UDP;
    } else if(args.find(e_ARG_INPUT_NIC) != args.end() &&
              args.find(e_ARG_OUTPUT_NIC) != args.end()){
       mode = e_MODE_BYPASS;
    } else if(args.find(e_ARG_INPUT_UDP) != args.end() &&
              args.find(e_ARG_OUTPUT_UDP) != args.end()){
        mode = e_MODE_UDP_TO_UDP;
    }

    switch (mode) {
        case e_MODE_BYPASS:
            th = new std::thread(thread_loop, args);
            break;
        case e_MODE_FILE_TO_UDP:
            th = new std::thread(thread_pcap, args);
            break;
        case e_MODE_UDP_TO_UDP:
            th = new std::thread(thread_sender, args);
            break;
        default:
            break;
    }
    while(true){
        sleep(1);
    }
    return 0;
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
    printf("%s, %s\n", inout.udp.c_str(), inout.adapter.c_str());
    return inout;
}

void thread_pcap(std::map<int, std::string> arg)
{
    PcapHeader mainhdr;
    PcapPacketHeader pkhdr;
    double first_time = 0;
    double pcap_curr_time = 0;
    struct timespec timespec_check;
    struct timespec timespec_1sec;
    int send_bitrate = 0;
    long long file_length;
    long long file_pos = 0;
    unsigned char ip_buffer[10240] = { 0, };
    ip_header_t ip_h;
    udp_header_t udp_h;
    bool use_output_nic = false;
    bool use_re_stamp = false;
    std::string path;
    sockaddr_in server_addr;
    u_int sock= 0;
    u_int addr_len = sizeof(struct sockaddr);
    FILE *file;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&server_addr, 0, addr_len);
    struct in_addr localInterface;
    auto output_nic = arg.find(e_ARG_OUTPUT_NIC);
    auto output_udp = arg.find(e_ARG_OUTPUT_UDP);
    InOutParam output_param;

    if(output_nic != arg.end()){
        use_output_nic = true;
    }
    if(output_udp != arg.end()){
        use_re_stamp = true;
        output_param = parse_inout(output_udp->second);
        auto addrs = split(output_param.udp, (char*)":");

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(std::stoi(addrs[1]));
        server_addr.sin_addr.s_addr = inet_addr(addrs[0].c_str());
        localInterface.s_addr = inet_addr(output_param.adapter.c_str());
        if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface, sizeof(localInterface)) < 0) {
            printf("setting local interface\n");
        }
    }
    if(use_output_nic == false && use_re_stamp){
        return;
    }

    file = fopen(path.c_str(), "rb");
    if (file == NULL) {
        printf("Err : %s\n", path.c_str());
    } else {
        printf("StartPcap : %s\n", path.c_str());
        usleep(1000000);
        fseek(file, 0, SEEK_END);
        file_length = ftell(file);
        fseek(file, 0, SEEK_SET);
        clock_gettime(CLOCK_MONOTONIC, &timespec_1sec);
        while (gRunning) {
            file_pos = 0;
            int read = fread(&mainhdr, 1, sizeof(mainhdr), file);
            first_time = 0;
            send_bitrate = 0;
            if (read > 0) {
                file_pos += read;
                while (file_length > file_pos && gRunning == true) {
                    read = fread(&pkhdr, 1, sizeof(pkhdr), file);
                    if (read > 0) {
                        file_pos += read;
                        if (first_time == 0) {
                            first_time = pkhdr.ts_sec + (pkhdr.ts_usec / 1000000.0);
                            clock_gettime(CLOCK_MONOTONIC, &timespec_check);
                        }
                        pcap_curr_time = pkhdr.ts_sec + (pkhdr.ts_usec / 1000000.0);
                        double time = pcap_curr_time - first_time;
                        while (gRunning) {
                            if (diff_time(timespec_check) >= time) {
                                break;
                            }
                            usleep(100);
                        }
                        read = fread(ip_buffer, 1, pkhdr.incl_len, file);
                        send_bitrate += read;
                        if (read > 0) {
                            file_pos += read;
                            if(use_output_nic){
                                parse_ip(ip_buffer, &ip_h);
                                parse_udp(ip_buffer + 20, &udp_h);

                                server_addr.sin_family = AF_INET;
                                server_addr.sin_port = htons(udp_h.dest_port);
                                server_addr.sin_addr.s_addr = htonl(ip_h.dest);
                            }
                            if (sendto(sock, ip_buffer + 28, read - 28, 0,
                                       (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
                            }
                            usleep(100);
                        }
                    }
                    if (diff_time(timespec_1sec) >= 1.0) {
                        clock_gettime(CLOCK_MONOTONIC, &timespec_1sec);
                        send_bitrate = 0;
                    }
                }
            }
            fseek(file, 0, SEEK_SET);
            usleep(1000);
        }
        fclose(file);
    }
}

void thread_loop(std::map<int, std::string> arg){
    char err[1024] = {0,};
    pcap_t* i_hdl;
    pcap_t* o_hdl;
    pcap_pkthdr pcap_pkt;
    i_hdl = pcap_open_live(arg[e_ARG_INPUT_NIC].c_str(), 2000, 1, 10, err);
    o_hdl = pcap_open_live(arg[e_ARG_OUTPUT_NIC].c_str(), 2000, 1, 10, err);
    while(gRunning){
        const uint8_t *packet = pcap_next(i_hdl, &pcap_pkt);
        pcap_sendpacket(o_hdl, packet, pcap_pkt.len);
        usleep(1);
    }
}

void thread_sender(std::map<int, std::string> arg)
{
    char err[1024] = {0,};
    ip_header_t ip_h;
    udp_header_t  udp_h;
    sockaddr_in server_addr;
    struct ip_mreq group;
    struct sockaddr_in c_addr;
    socklen_t c_len= 0;
    char buf[2048] = {0, };
    u_int sender= 0;
    u_int receiver = 0;
    u_int addr_len = sizeof(struct sockaddr);
    pcap_t* i_hdl;
    pcap_t* o_hdl;
    pcap_pkthdr pcap_pkt;
    receiver = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sender = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

    auto input_udp = arg.find(e_ARG_INPUT_UDP);
    auto output_udp = arg.find(e_ARG_OUTPUT_UDP);
    InOutParam output_param;
    InOutParam input_param;
    struct in_addr localInterface;
    input_param = parse_inout(input_udp->second);
    auto addrs = split(input_param.udp, (char *) ":");
    int recv_port = 0;

    server_addr.sin_family = PF_INET;
    server_addr.sin_addr.s_addr = inet_addr(input_param.adapter.c_str());

    if(bind(receiver, (struct  sockaddr*)&server_addr, addr_len) < 0){
        printf("error bind\n");
    }
    group.imr_multiaddr.s_addr = inet_addr(addrs[0].c_str());
    group.imr_interface.s_addr = inet_addr(input_param.adapter.c_str());

    if (setsockopt(receiver, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0) {
        printf("err\n");
    }else{
        printf("Join\n");
        printf("mcast : %s\n", addrs[0].c_str());
        printf("interface : %s\n", input_param.adapter.c_str());
        recv_port = std::stoi(addrs[1]);
    }
    if(output_udp != arg.end()) {
        output_param = parse_inout(output_udp->second);
        auto addrs = split(output_param.udp, (char *) ":");
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(std::stoi(addrs[1]));
        server_addr.sin_addr.s_addr = inet_addr(addrs[0].c_str());
        localInterface.s_addr = inet_addr(output_param.adapter.c_str());
        if (setsockopt(sender, IPPROTO_IP, IP_MULTICAST_IF, (char *) &localInterface, sizeof(localInterface)) < 0) {
            printf("setting local interface\n");
        }
    }

    i_hdl = pcap_open_live("enx00e04c691294", 2000, 1, 10, err);
    while(gRunning){
        const uint8_t *packet = pcap_next(i_hdl, &pcap_pkt);
        if(packet != NULL){
            parse_ip(packet + 14, &ip_h);
            parse_udp(packet + 14 + 20, &udp_h);
            if(udp_h.dest_port == recv_port){
                if(sendto(sender, packet + 28 + 14, pcap_pkt.len - 28 - 14, 0,
                          (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0 ){
                    printf("error, len:%d\n", pcap_pkt.len);
                }
            }
        }
        usleep(1);
    }
}
