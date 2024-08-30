#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> // To invoke the libpccap library and use its functions 
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <unistd.h>


#define APR_REQUEST  1
#define ARP_RESPONSE 2

// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr
{
    uint16_t htype;           // hardware type
    uint16_t ptype;           // protocal type
    uint8_t hlen;             // hardware address length
    uint8_t plen;             // protocal address length
    uint16_t opcode;          // operation code(APR request or responsse)
    uint8_t sender_mac[6];    // Sender hardware address
    uint8_t sender_ip[4];     // Sender ip address
    uint8_t target_mac[6];    // target hardware address
    uint8_t target_ip[4];     // target ip address
};

void alert_spoof(char* ip, char* mac)
{
    printf("ALERT:: Possible ARP spoofing Detected.");
}

void print_available_interface()
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t* interfaces, * temp;
    int i = 0;

    if (pcap_findalldevs(&interfaces, error) == -1)
    {
        printf("Can not acquire the devices\n");
        // return -1;
    }
    printf("The available interfaces are \n");
    for (temp = interfaces; temp; temp = temp->next)
    {
        printf("%d:%s\n", ++i, temp->name);
    }
}

void print_version()
{
    printf(" __  .___________.    ___       ______  __    __   __        __    __    ______  __    __   __   __    __       ___      \n ");
    printf("|  | |           |   /   \\     /      ||  |  |  | |  |      |  |  |  |  /      ||  |  |  | |  | |  |  |  |     /   \\     \n ");
    printf("|  | `---|  |----`  /  ^  \\   |  ,----'|  |__|  | |  |      |  |  |  | |  ,----'|  |__|  | |  | |  |__|  |    /  ^  \\    \n ");
    printf("|  |     |  |      /  /_\\  \\  |  |     |   __   | |  |      |  |  |  | |  |     |   __   | |  | |   __   |   /  /_\\  \\   \n ");
    printf("|  |     |  |     /  _____  \\ |  `----.|  |  |  | |  |      |  `--'  | |  `----.|  |  |  | |  | |  |  |  |  /  _____  \\  \n ");
    printf("|__|     |__|    /__/     \\__\\ \\______||__|  |__| |__|  _____\\______/   \\______||__|  |__| |__| |__|  |__| /__/     \\__\\ \n ");
    printf("                                                       |______|                                                          \n ");
    printf("           ___      .______      .______                                                                                 \n ");
    printf("          /   \\     |   _  \\     |   _  \\                                                                                \n ");
    printf("         /  ^  \\    |  |_)  |    |  |_)  |                                                                               \n ");
    printf("        /  /_\\  \\   |      /     |   ___/                                                                                \n ");
    printf("       /  _____  \\  |  |\\  \\----.|  |                                                                                    \n ");
    printf("      /__/     \\__\\ | _| `._____|| _|                                                                                    \n ");
    printf("                                                                                                                         \n ");
    printf("     _______..__   __.  __   _______  _______  _______ .______                                                           \n ");
    printf("    /       ||  \\ |  | |  | |   ____||   ____||   ____||   _  \\                                                          \n ");
    printf("   |   (----`|   \\|  | |  | |  |__   |  |__   |  |__   |  |_)  |                                                         \n ");
    printf("    \\   \\    |  . `  | |  | |   __|  |   __|  |   __|  |      /                                                          \n ");
    printf(".----)   |   |  |\\   | |  | |  |     |  |     |  |____ |  |\\  \\----.                                                     \n ");
    printf("|_______/    |__| \\__| |__| |__|     |__|     |_______|| _| `._____|                                                     \n ");
    printf("                                                                                                                         \n ");
    printf("                                                                                                                         \n ");
    printf("UCHIHA's ARP spoof detecetor v1.0\n");
}
void print_help(char* bin)
{

    printf("Available arguments: \n");
    printf("-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-\n");
    printf("-h or --help: \t \t \t print this help text \n");
    printf("-l or --lookup: \t \t Print the available interfaces\n");
    printf("-i or --interface: \t\t Provide the in terface to sniff on \n");
    printf("-v or --version :\t\t Print the sniff toll version \n");
    printf("Usage : %s -i <interface >  [You can look for the available interface using -l or --lookup]\n", bin);
    exit(1);
}

char* get_hardware_address(uint8_t mac[6])
{
    char* m = (char*)malloc(20 * sizeof(char));
    sprintf(m, "%2X:%2X:%2X:%2X:%2X:%2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return m;

}

char* get_ip_address(uint8_t ip[4])
{
    char* i = (char*)malloc(20 * sizeof(char));
    sprintf(i, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return i;
}

int sniff_arp(char* device_name)
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_t* packet_desc;

    u_char* hardW_ptr;
    int i;

    const u_char* packet;
    struct pcap_pkthdr header;
    struct ether_header* eptr;  // this struct included from if_ether
    arp_hdr* arpheader = NULL;
    char* t_mac, * t_ip, * s_mac, * s_ip;

    // For check the time diff between packets
    int counter;
    time_t curr_time, last_time;
    long int time_diff = 0;

    printf("BEFORE\n");
    packet_desc = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
    printf("after\n");
    if (packet_desc == NULL)
    {
        printf("packet_desc:: %s\n", error);
        print_available_interface();
        return -1;
    }
    else {
        printf("\nListening on..\n");
    }

    while (1)
    {
        packet = pcap_next(packet_desc, &header);
        if (packet == NULL)
        {
            printf("ERROR can not capture packets:: %s\n", error);
            return -1;
        }
        else
        {
            eptr = (struct ether_header*)packet;
            if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
            {
                curr_time = time(NULL);
                time_diff = curr_time - last_time;
                printf("time difference = %ld\n", time_diff);

                if (time_diff > 20)
                {
                    counter = 0;
                }
                arpheader = (arp_hdr*)(packet + 14);
                printf("\nReceived a packet with length %d\n", header.len);
                printf("Received at: %s\n", ctime((const time_t*)&header.ts.tv_sec));
                printf("Ethernet address length is %d\n", ETHER_HDR_LEN);

                printf("Opearation type ::%s\n", (ntohs(arpheader->opcode) == APR_REQUEST) ? "APR Request"
                    : "APR Response");

                s_mac = get_hardware_address(arpheader->sender_mac);
                printf("Sender mac::%s", s_mac);
                s_ip = get_ip_address(arpheader->sender_ip);
                printf("Sender ip ::%s", s_ip);
                t_mac = get_ip_address(arpheader->target_mac);
                printf("Target mac::%s", t_mac);
                t_ip = get_ip_address(arpheader->target_ip);
                printf("Target  ip :: %s", t_ip);
                printf("\n ------------------------------------");

                counter++;
                if (counter > 10)
                {
                    alert_spoof(s_ip, s_mac);
                }
                last_time = time(NULL);
            }
        }
    }
    return 0;
}
int main(int argc, char* argv[])
{
    // argv[0] => outputfile name

    if (access("/usr/bin/notify-send", F_OK) == -1)
    {
        printf("Missing dependency : libnotify-bin\n");
        printf("Please run: sudo apt-get install libnotify-bin");
        printf("\n");
        print_version();
        exit(-1);
    }
    for (int i = 0; i < argc; i++)
    {
        printf("argv[%d] == %s \n", i, argv[i]);
    }


    if ((argc < 2) || (strcmp("-h", argv[1]) == 0) || (strcmp("--help", argv[1]) == 0))
    {
        print_version();
        print_help(argv[0]);
    }
    else if ((strcmp("-v", argv[1]) == 0) || (strcmp("--version", argv[1]) == 0))
    {
        print_version();
    }
    else if ((strcmp("-l", argv[1]) == 0) || (strcmp("--lookup", argv[1]) == 0))
    {
        print_available_interface();
    }
    else if ((strcmp("-i", argv[1]) == 0) || (strcmp("--interface", argv[1]) == 0))
    {
        if (argc < 3)
        {
            printf("Please provide the interface name for sniffing. Select from the following \n");
            print_available_interface();
            printf("Usage : %s -i <interface >  [You can look for the available interface using -l or --lookup]\n", argv[0]);
        }
        sniff_arp(argv[2]);
    }
    else {
        printf("Invalid argument...\n");
        print_help(argv[0]);
    }
}