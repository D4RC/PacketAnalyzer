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