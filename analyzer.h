#ifndef _READER_H_
#define _READER_H_

#include <pcap.h>
#include <stdlib.h>

#include <arpa/inet.h>  // for inet_ntoa() [IPv4 Address format]
#include <net/ethernet.h>

#include <netinet/ip.h> // declarations for ip headers
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <unistd.h>
#include <signal.h>
#include <sys/ipc.h>

// Daemon related functions
void create_daemon();
void die_err();

// Analyzer functions
void start_analyzer();
void end_analyzer();
void help();
void print_packet();

struct SPID {
    char desc[20];
    int pid;
};

#endif //_READER_H