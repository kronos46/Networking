#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> // To invoke the libpccap library and use its functions 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int main()
{
    char *device_name, *net_addr, *net_mask;
    int return_code;
    char error[PCAP_ERRBUF_SIZE];

    bpf_u_int32 net_addr_int_val, net_mask_int_val; //  to store the IP Address as usigned 32 bit interger 
    struct in_addr addr;

    // we ask pcap to give us a valid eth based device to sniff oin it
    device_name = pcap_lookupdev(error);
    if(device_name == NULL)
    {
     printf("%s\n", error);
        return -1;
    }


    // From the device we received from pcap  we need to get the ip address and the subnet mask
    return_code = pcap_lookupnet(device_name, &net_addr_int_val, &net_mask_int_val, error);
    if(return_code == -1)
    {
        printf("%s\n", error);
        return -1;
    }

    // Convet the 32 bit int of IP and MASK in to the human readable form

    addr.s_addr = net_addr_int_val;
    net_addr = inet_ntoa(addr); // Used to convert the 32 bit ip to the printable  string 

    if(net_addr == NULL)
    {
        printf("ERROR  converting ip inet_ntoa() converstion ");

    }
    printf("NET ADDRESS : %s\n", net_addr);


    addr.s_addr = net_mask_int_val;
    net_mask = inet_ntoa(addr);
    if(net_mask == NULL)
    {
        printf("ERROR  converting MAST inet_ntoa() converstion ");

    }
    printf("NET MASK  : %s\n", net_mask);

    return 0;

}