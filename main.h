//
// Created by mini.cho on 2020/11/06.
//

#ifndef LOOPBACK_MAIN_H
#define LOOPBACK_MAIN_H

#include "src/common.h"

void thread_pcap(std::map<int, std::string> arg);
void thread_sender(std::map<int, std::string> arg);
void thread_loop(std::map<int, std::string>arg);
bool gRunning = true;


#endif //LOOPBACK_MAIN_H
