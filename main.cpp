#include <cstring>
#include <math.h>
#include "main.h"

int main(int argc, char **argv)
{
    GREEN("VERSION:%s\n", VERSION);
    GREEN("Copyright MARUENG, john\n\n");
    int mode = 0;
    std::thread *th = NULL;
    auto networks = GetNetworkInterface();
    YELLOW("Network Interfaces\n");
    for(auto it: networks){
        printf("[%s] %s\n", it.interface, it.address);
    }
    std::map<int, std::string> args;
    make_map();
    if(argc <= 1){
        YELLOW("\nUnknown arguments\n");
        help_print();
        return -1;
    }
    int rs = parse_arg(argc,argv, args);
    switch (rs){
        case e_ARG_VERSION:
        case e_ARG_HELP:
        case e_ARG_EXCEPT:
            RED("ERROR Param\n");
            help_print();
            return 0;
        default:
            break;
    }

    if(args.find(e_ARG_INPUT_PCAP) != args.end()) {
        mode = e_MODE_FILE_TO_UDP;
    } else if(args.find(e_ARG_MODE) != args.end()){
        auto mode_s = args[e_ARG_MODE];
        if (mode_s == "pcap2file") {
            mode = e_MODE_PCAP_TO_FILE;
        } else if (mode_s == "dstp2pcap") {
            mode = e_MODE_DSTP_PCAP_TO_PCAP;
        }else {
            YELLOW("Need 'pcap2file' or 'dstp2pcap' value\n");
            return 0;
        }
        if (args.find(e_ARG_INPUT_PCAP) != args.end() || args.find(e_ARG_OUTPUT_FILE) != args.end()) {
            YELLOW("Need 'pcap' and 'file' argument\n");
            return 0;
        }
    } else if(args.find(e_ARG_INPUT_NIC) != args.end() &&
              args.find(e_ARG_OUTPUT_NIC) != args.end()){
       mode = e_MODE_BYPASS;
    } else if(args.find(e_ARG_INPUT_UDP) != args.end() &&
              args.find(e_ARG_OUTPUT_UDP) != args.end()){
        mode = e_MODE_UDP_TO_UDP;
    }
    printf("\n\n");

    switch (mode) {
        case e_MODE_BYPASS:
            YELLOW("[Mode] Bypass Mode\n");
            th = new std::thread(thread_loop, args, networks);
            break;
        case e_MODE_FILE_TO_UDP:
            YELLOW("[Mode] Pcap Mode\n");
            th = new std::thread(thread_pcap, args, networks);
            break;
        case e_MODE_UDP_TO_UDP:
            YELLOW("[Mode] UDP to UDP\n");
            th = new std::thread(thread_sender, args, networks);
            break;
        case e_MODE_PCAP_TO_FILE:
            YELLOW("[Mode] PCAP to file\n");
            th = new std::thread(thread_pcap_to_file, args);
            break;
        case e_MODE_DSTP_PCAP_TO_PCAP:
            YELLOW("[Mode] DSTP pcap to pcap\n");
            th = new std::thread(thread_dstp_pcap_to_pcap, args);
            break;
        default:
            break;
    }
    th->join();
    return 0;
}


void thread_pcap(std::map<int, std::string> arg, std::list<Ethernet> networks)
{
    PcapHeader mainhdr;
    PcapPacketHeader pkhdr;
    double first_time = 0;
    double pcap_curr_time = 0;
    timespec timespec_check;
    timespec timespec_1sec;
    long long file_length;
    long long file_pos = 0;
    unsigned char ip_buffer[10240] = { 0, };
    ip_header_t ip_h;
    udp_header_t udp_h;
    unsigned int filter_ip_dst = 0;
    unsigned short filter_udp_dst = 0;
    bool use_output_nic = false;
    bool use_re_stamp = false;
    bool use_filter = false;
    std::string path;
    sockaddr_in server_addr;
    int send_bytes = 0;
    u_int sock= 0;
    u_int addr_len = sizeof(struct sockaddr);
    FILE *file;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&server_addr, 0, addr_len);
    in_addr localInterface;
    auto pcap_path = arg.find(e_ARG_INPUT_PCAP);
    auto output_nic = arg.find(e_ARG_OUTPUT_NIC);
    auto output_udp = arg.find(e_ARG_OUTPUT_UDP);
    auto input_filter = arg.find(e_ARG_INPUT_FILTER);
    InOutParam output_param;
    setlocale(LC_NUMERIC, "");

    if(output_nic != arg.end()){
        for(auto it: networks){
            std::string interface = it.interface;
            if(output_nic->second.compare("lo") == 0){
                localInterface.s_addr = inet_addr(it.address);
                if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface, sizeof(localInterface)) < 0) {
                    printf("setting local interface\n");
                }
                use_output_nic = true;
                printf("OutputNIC[lo], 127.0.0.1\n");
                break;
            }
            if(output_nic->second.compare(interface) == 0){
                localInterface.s_addr = inet_addr(it.address);
                if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface, sizeof(localInterface)) < 0) {
                    printf("setting local interface\n");
                }
                use_output_nic = true;
                printf("OutputNIC[%s], %s\n", it.interface, it.address);
                break;
            }
        }
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
        printf("Don't Use both -o -output");
        return;
    }
    if(input_filter != arg.end()){
        use_filter = true;
        auto filter = parse_inout(input_filter->second);
        auto addrs = split(filter.udp, (char*)":");
        u_int ip_dst = 0;
        if(addrs.size() == 2){
            auto ip_v = split(addrs.front(), (char*)".");
            int i = 3;
            for (auto it: ip_v){
                auto num = atoi(it.c_str());
                ip_dst += (num * pow(256, i));
                i -= 1;
            }
            filter_ip_dst = ip_dst;
        }
        filter_udp_dst = std::stoi(addrs[1]);
    }

    if(pcap_path != arg.end()){
       path = pcap_path->second;
    }

    file = fopen(path.c_str(), "rb");
    if (file == NULL) {
        RED("ERROR PCAP Open : %s\n", path.c_str());
    } else {
        YELLOW("StartPcap : %s\n", path.c_str());
        usleep(1000000);
        fseek(file, 0, SEEK_END);
        file_length = ftell(file);
        fseek(file, 0, SEEK_SET);
        clock_gettime(CLOCK_MONOTONIC, &timespec_1sec);
        while (gRunning) {
            file_pos = 0;
            int read = fread(&mainhdr, 1, sizeof(mainhdr), file);
            first_time = 0;
            send_bytes = 0;
            long long send_bytes_total = 0;
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
                        if (read > 0) {
                            file_pos += read;
                            bool skip = false;
                            parse_ip(ip_buffer + 14, &ip_h);
                            parse_udp(ip_buffer + 14 + 20, &udp_h);

                            if(use_filter){
                                if(ip_h.dest != filter_ip_dst || udp_h.dest_port != filter_udp_dst){
                                    continue;
                                }
                            }

                            if(use_re_stamp){

                            }
                            else if(use_output_nic){
                                server_addr.sin_family = AF_INET;
                                server_addr.sin_port = htons(udp_h.dest_port);
                                server_addr.sin_addr.s_addr = htonl(ip_h.dest);
                            }

                            if (sendto(sock, ip_buffer + 14 + 28, read - 14 - 28, 0,
                                       (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
                            }else{
                                send_bytes += read - 28;
                            }
                            usleep(100);
                        }
                    }
                    if (diff_time(timespec_1sec) >= 1.0) {
                        send_bytes_total += (long long)send_bytes;
                        clock_gettime(CLOCK_MONOTONIC, &timespec_1sec);
                        auto percent = (double)send_bytes_total / (double)file_length * 100.0;
                        printf("Sending : %'d bytes, Process : %.2f %\n", send_bytes, percent);
                        send_bytes = 0;
                    }
                }
            }
            fseek(file, 0, SEEK_SET);
            YELLOW("Loop %s\n", path.c_str());
            usleep(1000);
        }
        fclose(file);
    }
}

void thread_loop(std::map<int, std::string> arg, std::list<Ethernet> networks){
    char err[1024] = {0,};
    pcap_t* i_hdl;
    pcap_t* o_hdl;
    pcap_pkthdr pcap_pkt;
    i_hdl = pcap_open_live(arg[e_ARG_INPUT_NIC].c_str(), 2000, 1, 10, err);
    o_hdl = pcap_open_live(arg[e_ARG_OUTPUT_NIC].c_str(), 2000, 1, 10, err);
    timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    int loop_bytes = 0;
    while(gRunning){
        const uint8_t *packet = pcap_next(i_hdl, &pcap_pkt);
        pcap_sendpacket(o_hdl, packet, pcap_pkt.len);
        if(diff_time(time) >= 1.0){
            clock_gettime(CLOCK_MONOTONIC, &time);
            printf("[%s > %s]  %'d bytes\n", arg[e_ARG_INPUT_NIC].c_str(), arg[e_ARG_OUTPUT_NIC].c_str(), loop_bytes);
            loop_bytes = 0;
        }
        loop_bytes += pcap_pkt.len;
        usleep(1);
    }
}

int thread_pcap_to_file(std::map<int, std::string> arg)
{
    PcapHeader global_header;
    PcapPacketHeader packet_header;
    unsigned char ip_buffer[10240] = { 0, };

    auto input_path = arg.find(e_ARG_INPUT_PCAP);
    auto output_path = arg.find(e_ARG_OUTPUT_FILE);

    FILE* r_file = fopen(input_path->second.c_str(), "rb");
    if (r_file == nullptr) {
        printf("Error Open Read File= %s\n", input_path->second.c_str());
        return -1;
    }
    FILE* w_file = fopen(output_path->second.c_str(), "wb");
    if (w_file == nullptr) {
        printf("Error Open Write File= %s\n", output_path->second.c_str());
        fclose(r_file);
        return -1;
    }

    fseek(r_file, 0, SEEK_END);
    auto file_length = ftell(r_file);
    fseek(r_file, 0, SEEK_SET);
    printf("Start Pcap To Raw\n");

    int read = fread(&global_header, 1, sizeof(global_header), r_file);
    if (read > 0) {
        int file_pos = read;
        if(global_header.magic_number != PCAP_MAGIC_NUMBER){
            printf("%u, %u\n", global_header.magic_number, PCAP_MAGIC_NUMBER);
            fclose(r_file);
            fclose(w_file);
            printf("Error Pcap Header\n");
            return -1;
        }
        fwrite(&global_header, 1, sizeof(global_header), w_file);
        while (file_length > file_pos) {
            read = fread(&packet_header, 1, sizeof(packet_header), r_file);
            if (read > 0) {
                file_pos += read;
                read = fread(ip_buffer, 1, packet_header.incl_len, r_file);
                if (read > 0) {
                    file_pos += read;
                    read -= MAC_IP_UDP_HEADER_LENGTH;

                    // for Write Raw
                    fwrite(ip_buffer + MAC_IP_UDP_HEADER_LENGTH, 1, read, w_file);
                }
            }else {
                break;
            }
        }
    }else {
        printf("Error Read Pcap Header\n");
        return -1;
    }
    return 0;
}



int thread_dstp_pcap_to_pcap(std::map<int, std::string> arg)
{
    PcapHeader global_header;
    PcapPacketHeader packet_header;
    unsigned char packet[65535] = { 0, };
    unsigned char tmp_buffer[65535] = { 0, };

    FILE* r_file;
    FILE* w_file;

    auto input_path = arg.find(e_ARG_INPUT_PCAP);
    auto output_path = arg.find(e_ARG_OUTPUT_FILE);

    r_file = fopen(input_path->second.c_str(), "rb");
    if (r_file == nullptr) {
        printf("Error Open Read File= %s\n", input_path->second.c_str());
        return -1;
    }
    w_file = fopen(output_path->second.c_str(), "wb");
    if (w_file == nullptr) {
        printf("Error Open Write File= %s\n", output_path->second.c_str());
        fclose(r_file);
        return -1;
    }


    int es_count = 0;
    unsigned short prev_seq = 0;
    bool first_es = true;

    printf("Start DstpPcap To Pcap\n");

    fseek(r_file, 0, SEEK_END);
    auto file_length = ftell(r_file);
    fseek(r_file, 0, SEEK_SET);

    int read = fread(&global_header, 1, sizeof(global_header), r_file);
    if (read > 0) {
        int file_pos = read;
        if(global_header.magic_number != PCAP_MAGIC_NUMBER){
            printf("%u, %u\n", global_header.magic_number, PCAP_MAGIC_NUMBER);
            printf("Error Pcap Header\n");
            return -1;
        }
        fwrite(&global_header, 1, sizeof(global_header), w_file);

        while (file_length > file_pos) {
            read = fread(&packet_header, 1, sizeof(packet_header), r_file);
            if (read > 0) {
                file_pos += read;
                read = fread(packet, 1, packet_header.incl_len, r_file);
                if (read > 0) {
                    ip_header_t ip;
                    udp_header_t udp;
                    RtpHeader rtp;
                    unsigned char mac[14] = {0, };
                    file_pos += read;
                    ParseIp(packet + MAC_HEADER_LENGTH, &ip);
                    if(ip.protocol == 17){
                        int body_len = packet_header.incl_len - MAC_IP_UDP_RTP_HEADER_LENGTH;
                        memcpy(mac, packet, MAC_HEADER_LENGTH);
                        ParseUdp(packet + MAC_HEADER_LENGTH + IP_HEADER_LENGTH, &udp);
                        ParseRtp(packet + MAC_IP_UDP_HEADER_LENGTH, &rtp);
                        unsigned char *body = packet + MAC_IP_UDP_RTP_HEADER_LENGTH;
                        if (rtp.payload_Type != 81) {
                            printf("Not Dstp\n");
                            continue;
                        }
                        if (first_es) {
                            if (rtp.Marker == 1) {
                                first_es = false;
                                memcpy(tmp_buffer, body + rtp.Packet_Offset, body_len - rtp.Packet_Offset);
                                es_count = body_len - rtp.Packet_Offset;
                                prev_seq = rtp.SequenceNum;
                            }
                            continue;
                        }
                        prev_seq += 1;
                        if (rtp.SequenceNum != prev_seq) {
                            printf("RTP Continuity Error\n");
                            prev_seq = rtp.SequenceNum;
                            continue;
                        }
                        if (rtp.Marker == 1) {
                            if (rtp.Packet_Offset == 0) {
                                memcpy(tmp_buffer + es_count, body, body_len);
                                es_count += body_len;
                            }else {
                                memcpy(tmp_buffer + es_count, body, rtp.Packet_Offset);
                                es_count += rtp.Packet_Offset;
                            }
                            int count = 0;
                            while (count < es_count) {
                                unsigned char *in_packet = tmp_buffer + count;
                                DstpHeader dstp = {};
                                int dstp_header_len = ParseDstp(in_packet, &dstp);
                                if (count + dstp_header_len + dstp.length > es_count) {
                                    break;
                                }
                                count += dstp_header_len;
                                count += dstp.length;

                                // for Write Pcap
                                PcapPacketHeader pkt_header = {};
                                pkt_header.ts_sec = packet_header.ts_sec;
                                pkt_header.ts_usec = packet_header.ts_usec;
                                pkt_header.orig_len = dstp.length + 14;
                                pkt_header.incl_len= pkt_header.orig_len;
                                fwrite(&pkt_header, 1, sizeof(pkt_header), w_file);
                                fwrite(mac, 1, sizeof(mac), w_file);
                                fwrite(in_packet + dstp_header_len, 1, dstp.length, w_file);
                            }
                            if (count != es_count) {
                                memmove(tmp_buffer, tmp_buffer + count, es_count - count);
                                es_count -= count;
                            }else {
                                es_count = 0;
                            }
                            if (rtp.Packet_Offset != 0) {
                                memcpy(tmp_buffer, body + rtp.Packet_Offset, body_len - rtp.Packet_Offset);
                                es_count = body_len - rtp.Packet_Offset;
                            }
                        }else {
                            memcpy(tmp_buffer +es_count, body, body_len);
                            es_count += body_len;
                        }
                    }
                }
            }
        }
    }else {
        printf("Error Read Pcap Header\n");
        return -1;
    }
    return 0;
}
void thread_sender(std::map<int, std::string> arg, std::list<Ethernet> networks)
{
    char err[1024] = {0,};
    ip_header_t ip_h;
    udp_header_t  udp_h;
    sockaddr_in server_addr;
    struct ip_mreq group;
    u_int sender= 0;
    u_int receiver = 0;
    u_int addr_len = sizeof(struct sockaddr);
    pcap_t* i_hdl = NULL;
    pcap_t* o_hdl = NULL;
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
        printf("\n[Input UDP]\n");
        printf("UDP : %s\n", addrs[0].c_str());
        printf("Interface IP : %s\n", input_param.adapter.c_str());
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
        printf("\n[Output UDP]\n");
        printf("UDP : %s:%d\n", addrs[0].c_str(), std::stoi(addrs[1]));
        printf("Interface IP : %s\n", output_param.adapter.c_str());
    }

    for(auto it: networks){
        std::string ip = it.address;
        if(ip.compare(input_param.adapter) == 0){
            i_hdl = pcap_open_live(it.interface, 2000, 1, 10, err);
            break;
        }
    }

    if(i_hdl == NULL){
        printf("Input Error\n");
       return;
    }


    timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    int received_bytes = 0;
    int send_bytes = 0;
    int error_count = 0;
    setlocale(LC_NUMERIC, "");
    while(gRunning){
        const uint8_t *packet = pcap_next(i_hdl, &pcap_pkt);
        if(packet != NULL){
            parse_ip(packet + 14, &ip_h);
            parse_udp(packet + 14 + 20, &udp_h);
            if(udp_h.dest_port == recv_port){
                received_bytes += udp_h.length - 8;
                if(sendto(sender, packet + 28 + 14, pcap_pkt.len - 28 - 14, 0,
                          (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0 ){
                    error_count++;
                }else{
                    send_bytes += pcap_pkt.len - 28 - 14;
                }
            }
        }
        if(diff_time(time) >= 1.0){
            printf("[R] %'d bytes > [S] %'d bytes\n", received_bytes, send_bytes);
            if(error_count> 0){
                RED("SendError : %d\n", error_count);
            }
            received_bytes = 0;
            send_bytes = 0;
            error_count = 0;
            clock_gettime(CLOCK_MONOTONIC, &time);
        }
        usleep(1);
    }
}
