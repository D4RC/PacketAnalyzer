#ifndef _READER_H_
#define _READER_H_

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void device_selection();
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char *, int);
void print_ip_packet(const u_char *, int);
void print_tcp_packet(const u_char * , int );
void print_udp_packet(const u_char *, int);
void print_icmp_packet(const u_char *, int );
void print_data (const u_char *, int);

// Analyzer variables and data structures
struct SPID {
    char device[20];
    int pid;
};

char *device_name;
char errBuf[100];

//Handle to de device to analyze
pcap_t *handle; 

// Support files
#define INTERFACES "interfaces"

FILE *file, *flagstat, *interfaces, *logfile;

struct sockaddr_in source, dest;


#endif //_READER_H