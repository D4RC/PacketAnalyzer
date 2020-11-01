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
        //help();
        ;
    }
    else if(!strcmp(argv[1], "init"))
    {
        device_selection();
        start_analyzer(device_name);
    }
    else if(!strcmp(argv[1], "start"))
    {
        start_analyzer(argv[3]);
    }
    else if(!strcmp(argv[1], "stop"))
    {
        end_analyzer();
    }

    return 0;
}