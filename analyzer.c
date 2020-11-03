#include "analyzer.h"

/*
    @brief: Display the list of available network devices and require selection
*/
void device_selection()
{
    pcap_if_t *all_devices, *device;

    char devices[100][100];
    int count = 1, select;

    printf("Listing available devices ...\n");

    if(pcap_findalldevs(&all_devices, errBuf))
    {
        printf("Error finding devices : %s \n", errBuf);
        exit(1);
    }

    for(device = all_devices; device != NULL; device = device -> next)
    {
        printf("[%d] %s - %s \n", count, device->name, device->description);
        if(device->name != NULL)
            strcpy(devices[count++], device->name);
    }

    do 
    {
        printf("\nSelect a network device: \t");
        scanf("%d", &select);

        if(select > count | select < 0)
        {
            printf("Device %d not available, choose a valid device\n", count);
        }
        else
        {
            device_name = strdup(devices[select]);
        }
    }
    while(select > count | select <= 0);
}

/*
    @brief: Launches the analyzer in the specified interface
    @param interface: device to open (eth0, wlan0, etc...)
*/
void start_analyzer(char *interface)
{
    create_daemon(interface);

    char name[10];
    int flag= 1;

    interfaces = fopen(INTERFACES, "a+");

    while(!feof(interfaces))
    {
        if(!strcmp(name, interface))
        {
            flag = 0;
            break;
        }
        else
        {
            flag = 1;
        }
        fscanf(interfaces, "%s", name);
    }
    
    if(flag)
    {
        fseek(interfaces, SEEK_END, 1);
        fprintf(interfaces, "%s ", interface);
    }

    fclose(interfaces);
    device_name = interface;

    printf("Lauching packet capturing at interface\n");
    fflush(stdout);
    fflush(stdin);

    printf("Opening device: \t %s \n", device_name);
    handle = pcap_open_live(device_name, 65536, 1, 0, errBuf);

    if(!handle)
    {
        fprintf(stderr, "Couldn't open device %s, error: %s\n", device_name, errBuf);
        exit(1);
    }

    // Output file
    printf("Creating logfile : log.txt");
    logfile=fopen("log.txt", "w");
    if(!logfile)
        printf("Unable to create log file");

    printf(" ");
    // Put the device in sniff loop
    pcap_loop(handle, -1, process_packet, NULL);
}

void end_analyzer()
{
    pid_t pid;

    file = fopen("pids", "a+b");

    if(file == NULL)
        printf("pids error\n");
    
    struct SPID spid;
    fread(&spid, 1, sizeof(struct SPID), file);

    if(feof(file))
    {
        printf("Error\n");
        exit(1);
    }

    vector tmp;
    vector_init(&tmp);

    while(1)
    {
        if(feof(file)) 
            break;
        pid = spid.pid;
        vector_add(&tmp, spid.device);

        if(pid != -1)
            printf("Kill pid: %d\n", pid);
        if(pid != -1)
            kill(pid, SIGKILL);
        else 
            printf("program not runs\n");

        fread(&spid, 1, sizeof(struct SPID), file);
    }

    fclose(file);
    file = fopen("pids", "wb");
    int i;
    for(i=0;i < vector_count(&tmp);i++)
    {
        strcpy(spid.device, vector_get(&tmp, i));
        spid.pid = -1;
        fwrite(&spid, 1, sizeof(struct SPID), file);
    }

    remove("log.txt");
    remove("interfaces");
    remove("pids");


    vector_free(&tmp);
    fclose(file);
}

/*
    @brief: Callback function for pcap_loop sniffer, manages the corresponding packet type
*/
void process_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *buffer)
{
    int size = header->len;

    // Get the IP header excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    //++total;

    // Check the protcol and do accordingly
    switch(iph->protocol)
    {
        case 1:
            //++icmp;
            print_icmp_packet(buffer, size);
            break;
        case 6:
            //++tcp;
            print_tcp_packet(buffer, size);
            break;
        case 17:
            //++udp;
            print_udp_packet(buffer, size);
            break;
        default:
            //++others;
            break;
        
    }
}

/*
    @brief: Assigns PID, creates Daemon 
    @param dev: Name of the network device to analyze
*/
void create_daemon(char *dev)
{
    pid_t proc_id = 0;
    pid_t sid = 0;

    char name[10];
    int pid;
    int fl=1;

    printf("Creating daemon ... \n");
    proc_id = fork();

    if(proc_id < 0)
    {
        printf("Fork failed \n");
        exit(1);
    }
    if(proc_id > 0) // PARENT PROCESS - (>>KILL)
    {
        exit(0);
    }

    // New file permissions
    // umask(0);

    // New working directory
    // chdir("/");

    int k;
    for (k = sysconf(_SC_OPEN_MAX); k>=0; k--)
    {
        close(k);
    }

    sid = setsid(); // New session 
    if(sid < 0)
        exit(1);

    
    printf("Process ID:\t%d\n", sid);
    struct SPID spid;

    // Update knowledge base
    // Store the process ID in a file to track the Daemon  
    file = fopen("pids", "a+b");
    
    if(!file)
        printf("Error\n");
    
    fread(&spid, 1, sizeof(struct SPID), file);

    int steps = 0;
    int flag = 1;

    if(feof(file))  // First entry
    {
        fseek(file, 0, SEEK_SET);
        strcpy(spid.device, dev);
        spid.pid = sid;
        fwrite(&spid, 1, sizeof(struct SPID), file);
    }
    else            
    {
        while(1)
        {
            steps++;

            if(!strcmp(spid.device, dev))   // Device already registered
            {
                flag = 0;
                if(spid.pid != -1)          // Registered and Daemon already executing
                {
                    printf("Exec\n");
                    exit(0);
                }

                // Registered but not marked executing, update!
                int i;                      
                fclose(file);
                file = fopen("pids", "w+b");    
                for(int i = 0; i < steps - 1; i++)
                    fread(&spid, 1, sizeof(struct SPID), file);
                
                strcpy(spid.device, dev);
                spid.pid = sid;

                fwrite(&spid, 1, sizeof(struct SPID), file);
                break;
            }
            fread(&spid, 1, sizeof(struct SPID), file);     
            if(feof(file))
                break;
        }

        printf("\n");
        if(flag)
        {
            printf("Exec\n");
            fseek(file, 0, SEEK_END);
            strcpy(spid.device, dev);
            spid.pid = sid;
            printf("Track update, write (%s: %d)\n", spid.device, spid.pid);
            fwrite(&spid, 1, sizeof(struct SPID), file);
        }
    }
    fclose(file);
    printf("Done\n");
}

void sig_handler(int signal)
{
    printf("\n");

    if(signal == SIGUSR1)
    {
        printf("Done\n");
        printf("Process ID:\t%d\n", getpid());
    }
    else if(signal == SIGUSR2)
    {
        printf("Process ID:\t%d\n", getpid());
    }
    else
    {
        printf("Not handled");
    }
}

void print_ethernet_header(const unsigned char *buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *) buffer;

    fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet Header\n");
	fprintf(logfile, "\t Destination Address    : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
	fprintf(logfile, "\t Source Address         : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
	fprintf(logfile, "\t Protocol               : %u \n", (unsigned short)eth->h_proto);
}

void print_ip_header(const unsigned char *buffer, int size)
{
    print_ethernet_header(buffer, size);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph -> ihl * 4;

    // Clean socket address descriptors
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));

    // New descriptors
    source.sin_addr.s_addr = iph -> saddr;
    dest.sin_addr.s_addr = iph -> daddr;

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, "\t IP Version             : %d\n", (unsigned int) iph->version);
    fprintf(logfile, "\t Header Length          : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl, ((unsigned int)(iph->ihl))*4);
	fprintf(logfile, "\t Service Type           : %d\n", (unsigned int)iph->tos);
	fprintf(logfile, "\t IP Total Length        : %d Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	fprintf(logfile, "\t Identification         : %d\n", ntohs(iph->id));
	fprintf(logfile, "\t TTL                    : %d\n", (unsigned int)iph->ttl);
	fprintf(logfile, "\t Protocol               : %d\n", (unsigned int)iph->protocol);
	fprintf(logfile, "\t Checksum               : %d\n", ntohs(iph->check));
	fprintf(logfile, "\t Source IP              : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, "\t Destination IP         : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(const unsigned char *buffer, int size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
    struct tcphdr *tcph=(struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph -> doff*4;

    print_ip_header(buffer, size);

    fprintf(logfile, "\n\n-------------------------   TCP Packet   ---------------------------\n");
    
    fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, "\t Source Port            : %u\n", ntohs(tcph->source));
	fprintf(logfile, "\t Destination Port       : %u\n", ntohs(tcph->dest));
	fprintf(logfile, "\t Sequence Number        : %u\n", ntohl(tcph->seq));
	fprintf(logfile, "\t Acknowledge Number     : %u\n", ntohl(tcph->ack_seq));
	fprintf(logfile, "\t Header Length          : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(logfile, "\t Urgent Flag            : %d\n", (unsigned int)tcph->urg);
	fprintf(logfile, "\t Acknowledgement Flag   : %d\n", (unsigned int)tcph->ack);
	fprintf(logfile, "\t Push Flag              : %d\n", (unsigned int)tcph->psh);
	fprintf(logfile, "\t Reset Flag             : %d\n", (unsigned int)tcph->rst);
	fprintf(logfile, "\t Synchronise Flag       : %d\n", (unsigned int)tcph->syn);
	fprintf(logfile, "\t Finish Flag            : %d\n", (unsigned int)tcph->fin);
	fprintf(logfile, "\t Window                 : %d\n", ntohs(tcph->window));
	fprintf(logfile, "\t Checksum               : %d\n", ntohs(tcph->check));
	fprintf(logfile, "\t Urgent Pointer         : %d\n", tcph->urg_ptr);
	fprintf(logfile, "\n");
	fprintf(logfile, "                      DATA Dump                         ");
    fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	print_data(buffer, iphdrlen);
		
	fprintf(logfile, "TCP Header\n");
	print_data(buffer + iphdrlen,tcph->doff * 4);
		
	fprintf(logfile, "Data Payload\n");	
	print_data(buffer + header_size , size - header_size);
						
	fprintf(logfile, "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

}

void print_udp_packet(const unsigned char *buffer, int size)
{
    unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logfile, "\n\n-------------------------   UDP Packet   ---------------------------\n");
	
	print_ip_header(buffer, size);			
	
	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, "\t Source Port            : %d\n", ntohs(udph->source));
	fprintf(logfile, "\t Destination Port       : %d\n", ntohs(udph->dest));
	fprintf(logfile, "\t UDP Length             : %d\n", ntohs(udph->len));
	fprintf(logfile, "\t UDP Checksum           : %d\n", ntohs(udph->check));
    fprintf(logfile, "                      DATA Dump                         ");
    fprintf(logfile , "\n");
	
	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	print_data(buffer , iphdrlen);
		
	fprintf(logfile, "UDP Header\n");
	print_data(buffer+iphdrlen , sizeof udph);
		
	fprintf(logfile , "Data Payload\n");	
	//Move the pointer ahead and reduce the size of string
	print_data(buffer + header_size , size - header_size);
	fprintf(logfile, "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

void print_icmp_packet(const unsigned char *buffer, int size)
{
    unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	fprintf(logfile, "\n\n------------------------   ICMP Packet   ---------------------------\n");
	
	print_ip_header(buffer, size);
			
	fprintf(logfile, "\n");

	fprintf(logfile, "ICMP Header\n");
	fprintf(logfile, "\t Type                   : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile, "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile, "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logfile, "\t Code                   : %d\n",(unsigned int)(icmph->code));
	fprintf(logfile, "\t Checksum               : %d\n",ntohs(icmph->checksum));
	fprintf(logfile, "\n");
    fprintf(logfile, "                      DATA Dump                         ");
    fprintf(logfile , "\n");

	fprintf(logfile, "IP Header\n");
	print_data(buffer, iphdrlen);
		
	fprintf(logfile, "UDP Header\n");
	print_data(buffer + iphdrlen , sizeof icmph);
		
	fprintf(logfile, "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	print_data(buffer + header_size , (size - header_size) );
	fprintf(logfile, "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

/*
    @brief: Auxiliary function to print packet data
    @param data: Pointer to the buffer that contains the data
    @param size: Size of data
*/
void print_data(const unsigned char *data, int size)
{
    for(int i = 0; i < size; i++)
    {
        if(i != 0 && i%16 == 0) // Each hex line completion
        {
            fprintf(logfile, "\t\t");
            for(int j = i - 16; j < i; j++)
            {
                if(data[j] >= 32 && data[j] <= 128) // Alphanumerics
                    fprintf(logfile, "%c", (unsigned char)data[j]);
                else
                    fprintf(logfile, ".");
            }
            fprintf(logfile, "\n");
        }
        if(i % 16 == 0)
            fprintf(logfile, "\t\t");
        
        fprintf(logfile, " %02x", (unsigned int)data[i]);
    
        if(i == size - 1)   // Last line padding
        {
            for(int j = 0; j < 15 - i % 16; j++) 
			{
			    fprintf(logfile, "   ");
			}
			
			fprintf(logfile, "\t\t");
			
			for(int j = i - i % 16; j <= i; j++)
			{
			    if(data[j] >= 32 && data[j] <= 128) 
				{
				    fprintf(logfile, "%c", (unsigned char)data[j]);
				}
				else 
				{
				    fprintf(logfile, ".");
				}
			}
			
			fprintf(logfile, "\n");
        }
    }
}