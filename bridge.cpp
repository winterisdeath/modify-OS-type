#include <signal.h>
#include <pcap.h>

#include <thread>
#include <mutex>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include "packets_headers.h"
#include "mw.h"
#include <QMessageBox>
#include <QDebug>
#include "manual_wind.h"

/* Storage data structure used to pass parameters to the threads */
struct in_out_adapter
{
    unsigned int state;		/* Some simple state information */
    pcap_t *input_adapter;
    pcap_t *output_adapter;
};


/* Prototypes */
/* === WINDOWS === */
/* DWORD WINAPI CaptureAndForwardThread(LPVOID lpParameter); */
int capture_forward_thread(in_out_adapter &adapter);


void ctrlc_handler(int sig);


/* === WINDOWS === */
/* This prevents the two threads to mess-up when they do printfs */
// CRITICAL_SECTION print_cs;
std::mutex g_mutex;

/* === WINDOWS === */
/* Thread handlers. Global because we wait on the threads from the CTRL+C handler */
// HANDLE threads[2];


/* This global variable tells the forwarder threads they must terminate */
volatile int kill_forwaders = 0;

/* Print all devs */
pcap_if_t *print_all_devs(bool debug, int &count)
{
    pcap_if_t *alldevsp;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevsp, errbuf) != -1) {
        if (debug == true)
            for (pcap_if_t *dev = alldevsp; dev; dev = dev->next) {
                printf("%s\n", dev->name);
                count++;
            }
        return alldevsp;
    }
    else {
        return NULL;
    }
}

/* Get all devs */
QStringList get_all_devs()
{
    int count;
    pcap_if_t *alldevsp = print_all_devs(false, count);
    QStringList devs;
    for(pcap_if_t *d = alldevsp; d; d = d->next)
        devs.append(QString(d->name));
    pcap_freealldevs(alldevsp);
    //    qDebug() << devs;
    return devs;
}



/* For modify */

u_char* modify_packet(u_char*, u_int*);
uint16_t ip_checksum(const uint16_t* buf, size_t hdr_len);
unsigned short tcp_checksum(unsigned short *usBuf, int iSize);

const u_char Linux26x_SYN_Options[20] = { 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x8f, 0xb6, 0xc4, 0x0a, 0x00, 0x00, 0x00 ,0x00, 0x01, 0x03, 0x03, 0x01 };
const u_char Linux26x_SYN_ACK_Options[8] = { 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02 };
const u_char Windows_Options[8] = { 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02 };
const u_char Win_TTL = 128;
const u_char LinuxTTL = 64;
bool SYN = false;
int ppp = 0;


/* For checking the mode */
bool glob_auto;
bool glob_semi;
bool glob_manual;
bool glob_ttl;
bool glob_ip_src;
bool glob_ip_dst;

bool glob_drop = false;

/* For reading the parametres of semi-auto mode */
std::vector<int> ip_src_old;
std::vector<int> ip_src_new;
std::vector<int> ip_dst_old;
std::vector<int> ip_dst_new;

int ttl_old;
int ttl_new;
/*******************************************************************/

int mw::start_capturing()
{
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    int inum1, inum2;
    int i=0;
    pcap_t *adhandle1, *adhandle2;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask1, netmask2;
    char packet_filter[256];
    struct bpf_program fcode;
    in_out_adapter couple1, couple2;

    /*
     * Retrieve the device list
     */

    /* === WINDOWS === */
    /*
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    */

    /* Print the list */
    /*
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. ", ++i);
        if (d->description)
            printf("%s\n", d->description);
        else
            printf("<unknown adapter>\n");
    }
    */

    /* === cmd === */
    /*
    bool debug = true;
    alldevs = print_all_devs(debug, i);
    if(i == 0 && debug == true)
    {
        printf("\nNo interfaces found! Make sure LibPcap is installed.\n");
        return -1;
    }
    */

    bool debug = false;
    alldevs = print_all_devs(debug, i);
    inum1 = get_num_dev_1();
    inum2 = get_num_dev_2();
    if (inum1 == inum2) {
        QMessageBox::critical(this, QString("Error"), QString("You should choose different adapters!"));
        return  -1;
    }

    if (check_auto() == false && check_semi() == false && check_manual() == false) {
        QMessageBox::critical(this, QString("Error"), QString("You should choose mode of capturing!"));
        return  -1;
    }

    glob_auto = check_auto();
    glob_semi = check_semi();
    glob_manual = check_manual();
    glob_ttl = check_ttl();
    glob_ip_src = check_ip_src();
    glob_ip_dst = check_ip_dst();

    /*
     * Get input from the user
     */

    if (glob_semi) {
        if (glob_ttl) {
            ttl_old = get_ttl(1);
            ttl_new = get_ttl(2);
        }
        if (glob_ip_src) {
            ip_src_old = get_ip_src(1);
            ip_src_new = get_ip_src(2);
        }
        if (glob_ip_dst) {
            ip_dst_old = get_ip_src(1);
            ip_dst_new = get_ip_src(2);
        }
    }


    /* cmd -> GUI */

    /* Get the filter*/
    //    printf("\nSpecify filter (hit return for no filter):");
    //    fgets(packet_filter, sizeof(packet_filter), stdin);
    packet_filter[0] = '\0';


    /*
    // Get the first interface number
    printf("\nEnter the number of the first interface to use (1-%d):",i);
    //  scanf("%d", &inum1);  // OLD
    std::cin >> inum1;

    if(inum1 < 1 || inum1 > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs); // Free the device list
        return -1;
    }


    // Get the second interface number
    printf("Enter the number of the second"
           " interface to use (1-%d):",i);
    // scanf("%d", &inum2); // OLD
    std::cin >> inum2;

    if(inum2 < 1 || inum2 > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs); // Free the device list
        return -1;
    }

    if(inum1 == inum2 )
    {
        printf("\nCannot bridge packets on the same interface.\n");
        pcap_freealldevs(alldevs); // Free the device list
        return -1;
    }
*/


    /*
     * Open the specified couple of adapters
     */

    /* Jump to the first selected adapter */
    for(dev = alldevs, i = 0; i< inum1 - 1;  dev = dev->next, i++);

    /*
     * Open the first adapter.
     * *NOTICE* the flags we are using, they are important for the behavior of the prgram:
     *	- PCAP_OPENFLAG_PROMISCUOUS: tells the adapter to go in promiscuous mode.
     *    This means that we are capturing all the traffic, not only the one to or from
     *    this machine.
     *	- PCAP_OPENFLAG_NOCAPTURE_LOCAL: prevents the adapter from capturing again the packets
     *	  transmitted by itself. This avoids annoying loops.
     *	- PCAP_OPENFLAG_MAX_RESPONSIVENESS: configures the adapter to provide minimum latency,
     *	  at the cost of higher CPU usage.
     */

    /* === WINDOWS === */
    /*
     if((adhandle1 = pcap_open(d->name,						    // name of the device
                              65536,							// portion of the packet to capture.
                              // 65536 grants that the whole packet will be captured on every link layer.
                              PCAP_OPENFLAG_PROMISCUOUS |	// flags. We specify that we don't want to capture loopback packets, and that the driver should deliver us the packets as fast as possible
                              PCAP_OPENFLAG_NOCAPTURE_LOCAL |
                              PCAP_OPENFLAG_MAX_RESPONSIVENESS,
                              500,							// read timeout
                              NULL,							// remote authentication
                              errbuf							// error buffer
                              )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->description);
        pcap_freealldevs(alldevs); // Free the device list
        return -1;
    }
    */
    adhandle1 = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (adhandle1 == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
        exit(EXIT_FAILURE);
    }



    if(dev->addresses != NULL)
    {
        /* === WINDOWS === */
        /* Retrieve the mask of the first address of the interface */
        //  netmask1 = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
        //        netmask1 = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.s_addr;
        netmask1 = 0xffffff80;
    }
    else
    {
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask1 = 0xffffff;
    }

    /* Jump to the second selected adapter */
    for(dev = alldevs, i = 0; i< inum2 - 1; dev = dev->next, i++);

    /* === WINDOWS === */
    /* Open the second adapter */
    /*
    if((adhandle2 = pcap_open(d->name,						// name of the device
                              65536,							// portion of the packet to capture.
                              // 65536 grants that the whole packet will be captured on every link layer.
                              PCAP_OPENFLAG_PROMISCUOUS |	// flags. We specify that we don't want to capture loopback packets, and that the driver should deliver us the packets as fast as possible
                              PCAP_OPENFLAG_NOCAPTURE_LOCAL |
                              PCAP_OPENFLAG_MAX_RESPONSIVENESS,
                              500,							// read timeout
                              NULL,							// remote authentication
                              errbuf							// error buffer
                              )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->description);
        pcap_freealldevs(alldevs); // Free the device list
        return -1;
    }
    */
    adhandle2 = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (adhandle1 == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
        exit(EXIT_FAILURE);
    }

    if(dev->addresses != NULL)
    {
        /* === WINDOWS === */
        /* Retrieve the mask of the first address of the interface */
        //  netmask2 = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
        //        netmask2 = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.s_addr;
        netmask2 = 0xffffff80;
    }
    else
    {
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask2 = 0xffffff;
    }


    /*
     * Compile and set the filters
     */

    /* compile the filter for the first adapter */
    if (pcap_compile(adhandle1, &fcode, packet_filter, 1, netmask1) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");

        /* Close the adapters */
        pcap_close(adhandle1);
        pcap_close(adhandle2);

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* set the filter for the first adapter*/
    if (pcap_setfilter(adhandle1, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");

        /* Close the adapters */
        pcap_close(adhandle1);
        pcap_close(adhandle2);

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* compile the filter for the second adapter */
    if (pcap_compile(adhandle2, &fcode, packet_filter, 1, netmask2) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");

        /* Close the adapters */
        pcap_close(adhandle1);
        pcap_close(adhandle2);

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* set the filter for the second adapter*/
    if (pcap_setfilter(adhandle2, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");

        /* Close the adapters */
        pcap_close(adhandle1);
        pcap_close(adhandle2);

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* At this point, we don't need the device list any more. Free it */
    pcap_freealldevs(alldevs);

    /*
     * Start the threads that will forward the packets
     */

    /* === WINDOWS === */
    /* Initialize the critical section that will be used by the threads for console output */
    //    InitializeCriticalSection(&print_cs);

    /* Init input parameters of the threads */
    couple1.state = 1;
    couple1.input_adapter = adhandle1;
    couple1.output_adapter = adhandle2;
    couple2.state = 2;
    couple2.input_adapter = adhandle2;
    couple2.output_adapter = adhandle1;

    /* Start first thread */

    /* === WINDOWS === */
    /*
    if((threads[0] = CreateThread(
            NULL,
            0,
            CaptureAndForwardThread,
            &couple0,
            0,
            NULL)) == NULL)
    {
        fprintf(stderr, "error creating the first forward thread");

        // Close the adapters
        pcap_close(adhandle1);
        pcap_close(adhandle2);

        pcap_freealldevs(alldevs);  // Free the device list
        return -1;
    }
    */

    //    std::cout << "Opening first thread..." << std::endl;
    qDebug() << "Opening first thread...";
    std::thread thr_one(capture_forward_thread, std::ref(couple1));
    //    std::thread thr_one(capture_forward_thread, couple1);


    /* === WINDOWS === */
    /* Start second thread */
    /*
    if((threads[1] = CreateThread(
            NULL,
            0,
            CaptureAndForwardThread,
            &couple1,
            0,
            NULL)) == NULL)
    {
        fprintf(stderr, "error creating the second forward thread");

        // Kill the first thread. Not very gentle at all...
        TerminateThread(threads[0], 0);

        // Close the adapters
        pcap_close(adhandle1);
        pcap_close(adhandle2);

        pcap_freealldevs(alldevs); // Free the device list
        return -1;
    }
    */

    //    std::cout << "Opening second thread..." << std::endl;
    qDebug() << "Opening second thread...";
    std::thread thr_two(capture_forward_thread, std::ref(couple2));
    //    std::thread thr_two(capture_forward_thread, couple2);

    thr_one.join();
    thr_two.join();



    /*
     * Install a CTRL+C handler that will do the cleanups on exit
     */
    signal(SIGINT, ctrlc_handler);

    /*
     * Done!
     * Wait for the Greek calends...
     */
    printf("\nStart bridging the two adapters...\n");

    /* === WINDOWS === */
    //    sleep(INFINITE);
    sleep(800000);
    pcap_close(adhandle1);
    pcap_close(adhandle2);
    pcap_freealldevs(alldevs);

    return 0;
}

/*******************************************************************
 * Forwarding thread.
 * Gets the packets from the input adapter and sends them to the output one.
 *******************************************************************/

/* === WINDOWS === */
// DWORD WINAPI CaptureAndForwardThread(LPVOID lpParameter)
int capture_forward_thread(in_out_adapter& adapter)
{
    static int c = 0;
    std::cout << "In " << c << " thread!" << std::endl;
    c++;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res = 0;
    in_out_adapter* ad_couple = &adapter;
    unsigned int n_fwd = 0;

    /*
     * Loop receiving packets from the first input adapter
     */

    while((!kill_forwaders) && (res = pcap_next_ex(ad_couple->input_adapter, &header, &pkt_data)) >= 0)
    {
        if(res != 0)	/* Note: res=0 means "read timeout elapsed"*/
        {
            /*
             * Print something, just to show when we have activity.
             * BEWARE: acquiring a critical section and printing strings with printf
             * is something inefficient that you seriously want to avoid in your packet loop!
             * However, since this is a *sample program*, we privilege visual output to efficiency.
             */

            /* === WINDOWS === */
            /* EnterCriticalSection(&print_cs); */
            g_mutex.lock();

            if(ad_couple->state == 1) {
                /*======================= ЗДЕСЬ ИЗМЕНЯТЬ ПАКЕТЫ! =======================*/
                u_char* new_pkt = modify_packet((u_char*)pkt_data, &header->caplen);

                
                pkt_data = new_pkt;

                /* ============================== */

                printf(">> Len: %u\n", header->caplen);
                printf("   Data: %s\n", pkt_data);
            }
            else {
                printf("<< Len: %u\n", header->caplen);
            }
            /* === WINDOWS === */
            /* LeaveCriticalSection(&print_cs); */
            g_mutex.unlock();

            /*
             * Send the just received packet to the output adaper
             */
            if (glob_drop == false) {
                if(pcap_sendpacket(ad_couple->output_adapter, pkt_data, header->caplen) != 0)
                {
                    /* === WINDOWS === */
                    /* EnterCriticalSection(&print_cs); */
                    g_mutex.lock();

                    printf("Error sending a %u bytes packets on interface %u: %s\n",
                           header->caplen,
                           ad_couple->state,
                           pcap_geterr(ad_couple->output_adapter));

                    /* === WINDOWS === */
                    /* LeaveCriticalSection(&print_cs); */
                    g_mutex.unlock();
                }
                else
                {
                    n_fwd++;
                }
            }
            else
                glob_drop = false;
        }
    }

    /*
     * We're out of the main loop. Check the reason.
     */
    if(res < 0)
    {
        /* === WINDOWS === */
        /* EnterCriticalSection(&print_cs); */
        g_mutex.lock();


        printf("Error capturing the packets: %s\n", pcap_geterr(ad_couple->input_adapter));
        fflush(stdout);

        /* === WINDOWS === */
        /* LeaveCriticalSection(&print_cs); */
        g_mutex.unlock();
    }
    else
    {
        /* === WINDOWS === */
        /* EnterCriticalSection(&print_cs); */
        g_mutex.lock();

        printf("End of bridging on interface %u. Forwarded packets:%u\n",
               ad_couple->state,
               n_fwd);
        fflush(stdout);

        /* === WINDOWS === */
        /* LeaveCriticalSection(&print_cs); */
        g_mutex.unlock();
    }

    return 0;
}

/*******************************************************************
 * CTRL+C hanlder.
 * We order the threads to die and then we patiently wait for their
 * suicide.
 *******************************************************************/
void ctrlc_handler(int sig)
{
    /*
     * unused variable
     */
    (void)(sig);

    kill_forwaders = 1;
    sleep(2000);

    //    WaitForMultipleObjects(2,
    //                           threads,
    //                           TRUE,		/* Wait for all the handles */
    //                           5000);		/* Timeout */
//    exit(0);
}


u_char* modify_packet(u_char* Buffer, u_int *Size)
{
    /* My changing */

    /* auto mode */
    if (glob_auto)
        if (Buffer[12] == 0x08 && Buffer[13] == 0x00) {
            qDebug()<< "old buf: " << (int)Buffer[22];
            Buffer[22] = 64; /* Linux ttl */
            qDebug()  << "\new: " << (int)Buffer[22] << "\n";
            return Buffer;
        }

    /* semi mode */
    if (glob_semi) {
        if (glob_ttl)
            if (Buffer[12] == 0x08 && Buffer[13] == 0x00)
                if (ttl_old == 0 || ttl_old == Buffer[22]) {
                    qDebug()<< "old buf: " << (int)Buffer[22];
                    Buffer[22] = ttl_new;
                    qDebug()  << "\new: " << (int)Buffer[22] << "\n";
                }
        if (glob_ip_src)
            if ((Buffer[26] == ip_src_old[0] && Buffer[27] == ip_src_old[1]
                 && Buffer[28] == ip_src_old[2] && Buffer[29] == ip_src_old[3])
                    || (ip_src_old[0] == 0 && ip_src_old[1] == 0 && ip_src_old[2] == 0 && ip_src_old[3] == 0)) {
                qDebug()<< "old ip src: " << (int)Buffer[26] << "." << (int)Buffer[27] << "."
                        << (int)Buffer[28] << "." << (int)Buffer[29];
                Buffer[26] = ip_src_new[0];
                Buffer[27] = ip_src_new[1];
                Buffer[28] = ip_src_new[2];
                Buffer[29] = ip_src_new[3];
                qDebug()  << "\new: " << (int)Buffer[26] << "." << (int)Buffer[27] << "."
                          << (int)Buffer[28] << "." << (int)Buffer[29];
            }
        if (glob_ip_dst)
            if ((Buffer[30] == ip_dst_old[0] && Buffer[31] == ip_dst_old[1]
                 && Buffer[32] == ip_dst_old[2] && Buffer[33] == ip_dst_old[3])
                    || (ip_dst_old[0] == 0 && ip_dst_old[1] == 0 && ip_dst_old[2] == 0 && ip_dst_old[3] == 0)) {
                qDebug()<< "old ip dst: " << (int)Buffer[30] << "." << (int)Buffer[31] << "."
                        << (int)Buffer[32] << "." << (int)Buffer[33];
                Buffer[26] = ip_dst_new[0];
                Buffer[27] = ip_dst_new[1];
                Buffer[28] = ip_dst_new[2];
                Buffer[29] = ip_dst_new[3];
                qDebug()<< "old ip dst: " << (int)Buffer[30] << "." << (int)Buffer[31] << "."
                        << (int)Buffer[32] << "." << (int)Buffer[33];
            }
        return Buffer;
    }

    if (glob_manual) {
        manual_wind *wind = new manual_wind(Buffer, Size);
        wind->show();
        while(wind->end_modify == false && wind->drop == false) {
            continue;
        }


        if (wind->end_modify == true) {

            //            u_char *packet = new u_char[200];
            u_int size = 0;
            //            unsigned int *new_size;
            wind->get_packet(Buffer, size);

            qDebug() << "end " ;
            Size = &size;

            qDebug() << "new_s: " << (*Size);
            for (unsigned i = 0; i < *Size; i++)
                qDebug() << hex <<  Buffer[i];
        }

        if (wind->drop == true) {
            Buffer = 0;
            Size = 0;
            glob_drop = true;
            return 0;

        }
        wind->close();
        return Buffer;
    }




    /* ===================== */

    /* ==== Semchenkov code ==== */
    if ((Buffer[13] == 0x00) && (Buffer[23] == 0x06))
    {
        unsigned char tmp_hdr_ip[20];
        unsigned short tmpIP[10];

        memcpy(tmp_hdr_ip, Buffer + 14, 20);

        //#################### ����������� TCP-��������� #############################


        unsigned short ip_len = (tmp_hdr_ip[2] << 8) | tmp_hdr_ip[3];  // ����� IP-������ (�����, � TCP-���������)
        unsigned short tcp_size = ip_len - 20;  //  ������ TCP-�������� (TCP Header + TCP Data)
        unsigned short tcp_len = 0;
        if (ip_len % 2 == 1)
        {
            tcp_len = ip_len - 7;
        }  // ���� ����� ��������, �� ����������� �� 1
        else
        {
            tcp_len = ip_len - 8; // ����� TCP-�������� + ���������������
        }
        unsigned short *tmpTCP = new unsigned short[750]; // ����� 16-������ (�� 2 �����) ������� - ������������ �����������

        unsigned char *tmp_tcp = new unsigned char[1500];	// ����� ��� �������� TCP-�������� ��� ����������� (����������������� � tmpTCP ��� �������� � ������� tcp_checksum).

        //##################### ������������ ��������������� ##########################

        memcpy(tmp_tcp, Buffer + 26, 8);  // ���������� ��� ���������������
        tmp_tcp[8] = 0;
        tmp_tcp[9] = 6;
        tmp_tcp[10] = (unsigned char)(tcp_size >> 8);
        tmp_tcp[11] = (unsigned char)(tcp_size);

        // ################### ��������� ������������ ��������������� ####################

        memcpy(tmp_tcp + 12, Buffer + 34, tcp_size);

        //  #####################################  ���� ��������� ����� - � ������ SYN ####################################

        if (tmp_tcp[25] == 2) // TCP � ������������� ������ SYN
        {

            tmp_hdr_ip[2] = 0x00;
            // ����������� ���� IP Total Length
            tmp_hdr_ip[3] = 0x3c;

            ip_len = 60;

            tmp_tcp[24] = 0xa0;    // ����������� ���� TCP Header Length

            memcpy(tmp_tcp + 32, Linux26x_SYN_Options, 20);	 // ��������� ���� Options

            tcp_len = 52;   // ��������� ����� TCP-��������� � ���������������� (��� ������� tcp_checksum)

            tcp_size = 40;  // ��������� ����� TCP-���������

            tmp_tcp[10] = (unsigned char)(tcp_size >> 8);
            tmp_tcp[11] = (unsigned char)(tcp_size);

        }

        //  #####################################  ��������� ����������� SYN-������  #########################################



        //  #####################################  ���� ��������� ����� - � ������ SYN,ACK ####################################

        if (tmp_tcp[25] == 18) // TCP � ������������� ������ SYN,ACK
        {

            tmp_hdr_ip[2] = 0x00;
            // ����������� ���� IP Total Length
            tmp_hdr_ip[3] = 0x30;

            ip_len = 48;

            tmp_tcp[24] = 0x70;    // ����������� ���� TCP Header Length

            memcpy(tmp_tcp + 32, Linux26x_SYN_ACK_Options, 8);	 // ��������� ���� Options

            tcp_len = 40;   // ��������� ����� TCP-��������� � ���������������� (��� ������� tcp_checksum)

            tcp_size = 28;  // ��������� ����� TCP-���������

            tmp_tcp[10] = (unsigned char)(tcp_size >> 8);
            tmp_tcp[11] = (unsigned char)(tcp_size);

        }

        //  #####################################  ��������� ����������� SYN,ACK-������  #########################################


        tmp_tcp[28] = 0;
        //    ��������� ����������� �����
        tmp_tcp[29] = 0;

        tmp_tcp[26] = 0x16;
        //	����������� ���� Windows Size
        tmp_tcp[27] = 0xD0;



        for (int j = 0; j < tcp_len / 2; j++)
        {
            tmpTCP[j] = ((tmp_tcp[j * 2] << 8) & 0xFF00) | (tmp_tcp[j * 2 + 1] & 0xFF);
        }
        if (tcp_size % 2 == 1) tmpTCP[tcp_len / 2 - 1] = (tmpTCP[tcp_len / 2 - 1] & 0xFF00);

        unsigned short chk_sumTCP = tcp_checksum(tmpTCP, tcp_len);
        tmp_tcp[28] = (unsigned char)(chk_sumTCP >> 8);
        tmp_tcp[29] = (unsigned char)chk_sumTCP;

        memcpy(Buffer + 34, tmp_tcp + 12, tcp_size);



        //################## ��������� ����������� TCP-��������� ###############################


        //################## ����������� IP-��������� #################################

        tmp_hdr_ip[1] = 0x10;  // ����������� ���� Type Of Service (Differentiated Services Field)
        tmp_hdr_ip[6] = 0x00;  // ����������� ���� Flags (Don't Fragment bit)

        if (tmp_hdr_ip[8] - 60 < 10) tmp_hdr_ip[8] = 64;
        tmp_hdr_ip[8] = LinuxTTL;  // ����������� TTL

        tmp_hdr_ip[10] = 0;
        // ��������� ����������� �����
        tmp_hdr_ip[11] = 0;

        for (int i = 0; i < 10; i++)
        {
            tmpIP[i] = ((tmp_hdr_ip[i * 2] << 8) & 0xFF00) | (tmp_hdr_ip[i * 2 + 1] & 0xFF);
        }
        unsigned short chk_sumIP = ip_checksum(tmpIP, 20);
        tmp_hdr_ip[10] = (unsigned char)(chk_sumIP >> 8);
        tmp_hdr_ip[11] = (unsigned char)chk_sumIP;

        memcpy(Buffer + 14, tmp_hdr_ip, 20);

        *Size = ip_len + 14;

        delete[]tmpTCP;
        delete[]tmp_tcp;

        return Buffer;
    }
    else
    {

        return Buffer;
    }
}

uint16_t ip_checksum(const uint16_t* buf, size_t hdr_len)
{
    unsigned long sum = 0;
    const uint16_t *ip1;

    ip1 = buf;
    while (hdr_len > 1)
    {
        sum += *ip1++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        hdr_len -= 2;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return(~sum);
}

unsigned short tcp_checksum(unsigned short *usBuf, int iSize)
{
    unsigned long usChksum = 0;
    while (iSize > 1)
    {
        usChksum += *usBuf++;
        iSize -= sizeof(unsigned short);
    }

    if (iSize)
        usChksum += *(unsigned char*)usBuf;

    usChksum = (usChksum >> 16) + (usChksum & 0xffff);
    usChksum += (usChksum >> 16);

    return (unsigned short)(~usChksum);
}
