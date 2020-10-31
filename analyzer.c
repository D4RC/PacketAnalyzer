#include "analyzer.h"

void init()
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

    printf("\nSelect a network device: \t");
    scanf("%d", &select);
    device_name = devices[select];

    printf("Opening device: \t %s \n", device_name);
    handle = pcap_open_live(device_name, 65536, 1, 0, errBuf);

    if(!handle)
    {
        fprintf(stderr, "Couldn't open device, error: %s\n", errBuf);
        exit(1);
    }
}