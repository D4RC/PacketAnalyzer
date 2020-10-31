#include "analyzer.h"

int main(int argc, char **argv)
{

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
        //start_analyzer();
        ;
    }
    else if(!strcmp(argv[1], "stop"))
    {
        //end_analyzer();
        ;
    }

    init();
    return 0;
}