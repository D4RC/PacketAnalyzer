#include "analyzer.h"

int main(int argc, char **argv)
{
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sig_handler;
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);

    if(argc < 2)
    {
        printf("Incorrect number of arguments \n");
        printf("Use --help \n");
        exit(1);
    }
    else if(!strcmp(argv[1], "--help"))
    {
        printf("The application requires root or superuser privilege to work properly\n");
        printf("select an interface an start analyzer:     init\n");
        printf("start analyzer in an specific inerface:    start [interface]\n");
        printf("stop analyzer:                             stop\n");
    }
    else if(!strcmp(argv[1], "init"))
    {
        device_selection();
        start_analyzer(device_name);
    }
    else if(!strcmp(argv[1], "start"))
    {
        if(argv[2])
            start_analyzer(argv[2]);
        else
            printf("No specified device\n");
    }
    else if(!strcmp(argv[1], "stop"))
    {
        end_analyzer();
    }

    return 0;
}