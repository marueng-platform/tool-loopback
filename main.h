//
// Created by mini.cho on 2020/11/06.
//

#ifndef LOOPBACK_MAIN_H
#define LOOPBACK_MAIN_H

#include "src/common.h"

void thread_pcap(std::map<int, std::string> arg, std::list<Ethernet> networks);
void thread_sender(std::map<int, std::string> arg, std::list<Ethernet> networks);
void thread_loop(std::map<int, std::string>arg, std::list<Ethernet> networks);
bool gRunning = true;

#endif //LOOPBACK_MAIN_H
