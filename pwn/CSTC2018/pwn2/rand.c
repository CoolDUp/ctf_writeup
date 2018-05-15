#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) 
{
    int i;
    unsigned int seed;
    if (argc>1){ seed = strtoul(argv[1],0,0);}else { seed = time(0);}
    printf("%d\n",seed);
    for(srand(seed),i=0;i<1024;i++)printf("%d\n",rand());
    return 0;
}

