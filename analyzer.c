#include "analyzer.h"

/*
    @brief: Display the list of available network devices and require selection
*/
void device_selection()
{
    char errBuf[100];

    pcap_if_t *all_devices, *device;

    char devices[100][100], *device_name;
    int count = 1, select;

    pcap_t *handle; //Handle to de device to analyze

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
            printf("Device %d not available, choose a valid device\n");
        }
        else
        {
            device_name = devices[select];
        }
    }
    while(select > count | select <= 0);

    printf("Opening device: \t %s \n", device_name);
    handle = pcap_open_live(device_name, 65536, 1, 0, errBuf);

    if(!handle)
    {
        fprintf(stderr, "Couldn't open device, error: %s\n", errBuf);
        exit(1);
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

    //unmask(0);

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
        flose(file);
    }
}

/*
    @brief: Launches the analyzer
*/
void start_analyzer()
{
    char *device;
    create_daemon(device);

    char name[10];
    int flag= 1;

    flagstat = fopen(device, "w");
    interfaces = fopen(INTERFACES, "a+");

    while(!feof(interfaces))
    {
        if(!strcmp(name, device))
        {
            flagstat = 0;
            break;
        }
        else
        {
            flagstat = 1;
        }
        fscanf(interfaces, "%s", device);
    }
    fclise(interfaces);


}


void print_ethernet_header(const unsigned char *buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *) buffer;

    fprintf(LOGFILE, "\n");
	fprintf(LOGFILE, "Ethernet Header\n");
	fprintf(LOGFILE, "\t Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
	fprintf(LOGFILE, "\t Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
	fprintf(LOGFILE, "\t Protocol            : %u \n", (unsigned short)eth->h_proto);
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

    fprintf(LOGFILE, "\n");
    fprintf(LOGFILE, "IP Header\n");
    fprintf(LOGFILE, "\t IP Version         : %d\n", (unsigned int) iph->version);
    fprintf(LOGFILE, "\t Header Length      : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl, ((unsigned int)(iph->ihl))*4);
	fprintf(LOGFILE, "\t Service Type       : %d\n", (unsigned int)iph->tos);
	fprintf(LOGFILE, "\t IP Total Length    : %d Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	fprintf(LOGFILE, "\t Identification     : %d\n", ntohs(iph->id));
	fprintf(LOGFILE, "\t TTL                : %d\n", (unsigned int)iph->ttl);
	fprintf(LOGFILE, "\t Protocol           : %d\n", (unsigned int)iph->protocol);
	fprintf(LOGFILE, "\t Checksum           : %d\n", ntohs(iph->check));
	fprintf(LOGFILE, "\t Source IP          : %s\n", inet_ntoa(source.sin_addr));
	fprintf(LOGFILE, "\t Destination IP     : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(const unsigned char *buffer, int size)
{
    unsigned short iphdrlen;



}

void print_udp_packet(const unsigned char *buffer, int size)
{

}

void print_icmp_packet(const unsigned char *buffer, int size)
{

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
            fprintf(LOGFILE, "\t\t");
            for(int j = i - 16; j < i; j++)
            {
                if(data[j] >= 32 && data[j] <= 128) // Alphanumerics
                    fprintf(LOGFILE, "%c", (unsigned char)data[j]);
                else
                    fprintf(LOGFILE, ".");
            }
            fprintf(LOGFILE, "\n");
        }
        if(i % 16 == 0)
            fprintf(LOGFILE, "\t\t");
        
        fprintf(LOGFILE, " %02x", (unsigned int)data[i]);
    
        if(i == size - 1)   // Last line padding
        {
            for(int j = 0; j < 15 - i % 16; j++) 
			{
			    fprintf(LOGFILE, "   ");
			}
			
			fprintf(LOGFILE, "\t\t");
			
			for(int j = i - i % 16; j <= i; j++)
			{
			    if(data[j] >= 32 && data[j] <= 128) 
				{
				    fprintf(LOGFILE, "%c", (unsigned char)data[j]);
				}
				else 
				{
				    fprintf(LOGFILE, ".");
				}
			}
			
			fprintf(LOGFILE,  "\n" );
        }
    }
}