#include <signal.h>
#include <pcap.h>

#include "mw.h"

#include <thread>
#include <vector>
#include <mutex>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include <QMessageBox>
#include <QDebug>



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
pcap_if_t *print_all_devs(bool debug, int &count);

/* Get all devs */
QStringList get_all_devs();


/* For modify */

uchar* modify_packet(uchar* buffer, uint& size);
uchar* modify_nmap(uchar* buffer, uint& size);
ushort ip_sum(uchar *buffer);
ushort tcp_sum(uchar *buffer, ushort tcp_len);
ushort icmp_sum(uchar *buffer);
void get_os_params(os_sig os, bool type_param, ushort &win_size, uchar &ttl, uchar &df_bit,
                   std::vector<uchar> &options);

/* Modify params */
uchar ttl;
/* -- SYN-ACK params -- */
std::vector<uchar> syn_options;
ushort syn_ack_win_size;
uchar syn_ack_options_size;
uchar syn_ack_df_bit;

/* -- SYN params -- */
std::vector<uchar> syn_ack_options;
ushort syn_win_size;
uchar syn_options_size;
uchar syn_df_bit;


/* For checking the mode */
bool glob_mode;
bool host_mode;
os_sig os;

/* For reading the parametres of semi-auto mode */
std::vector<int> ip_host;

/*******************************************************************/

int mw::start_capturing()
{

    pcap_if_t *dev;
    int inum1, inum2;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint netmask1, netmask2;
    char packet_filter[256];


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
        QMessageBox::critical(this, "Error", "Select different adapters!");
        return -1;
    }
    /*
     * Get input from the user
     * 0 - auto mode
     * 1 - semi-auto mode
     */
    glob_mode = ui->tabWidget->currentIndex();

    /*
     * Check protected hosts
     * 0 - all host
     * 1 - required host
     */
    if (ui->rb_host_all->isChecked()) {
        host_mode = false;
    }
    else {
        host_mode = true ;
        ip_host = get_ip_host();
    }


    /* Get OS num to read fingerprint */
    int ind = ui->cb_os_type->currentIndex();
    os = os_list.at(ind);

    /* type_param
     * 0 - S
     * 1 - SA
     */
    get_os_params(os, 0, syn_win_size, ttl, syn_df_bit, syn_options);
    get_os_params(os, 1, syn_ack_win_size, ttl, syn_ack_df_bit, syn_ack_options);
    //    qDebug() << os.s_params;
    //    qDebug() << hex << "syn:     " << syn_options;
    //    qDebug() << os.sa_params;
    //    qDebug() << hex << "syn-ack: " << syn_ack_options;


    /* cmd -> GUI */

    /* Get the filter*/
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
        netmask1 = 0xffffff00;
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
        netmask2 = 0xffffff00;
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

    //    std::qDebug()<< "Opening first thread..." << std::endl;
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

    //    std::qDebug()<< "Opening second thread..." << std::endl;
    qDebug() << "Opening second thread...";
    std::thread thr_two(capture_forward_thread, std::ref(couple2));
    //    std::thread thr_two(capture_forward_thread, couple2);

    thr_one.detach();
    thr_two.detach();
    //    thr_one.join();
    //    thr_two.join();




    /*
                     * Install a CTRL+C handler that will do the cleanups on exit
                     */
    //    signal(SIGINT, ctrlc_handler);

    /*
                     * Done!
                     * Wait for the Greek calends...
                     */
    //    printf("\nStart bridging the two adapters...\n");

    /* === WINDOWS === */
    //    sleep(INFINITE);

    /*sleep(800000);
                    pcap_close(adhandle1);
                    pcap_close(adhandle2);
                    pcap_freealldevs(alldevs);
                    */
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
    qDebug()<< "In " << c << " thread!";
    c++;
    struct pcap_pkthdr *header;
    const uchar *pkt_data;
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
                /* Protect required IP */
                if (host_mode == true) {
                    if ((pkt_data[0x0c] == 0x08) && (pkt_data[0x0d] == 0x00))
                        if (pkt_data[0x1a] == ip_host[0] && pkt_data[0x1b] == ip_host[1]
                                && pkt_data[0x1c] == ip_host[2] && pkt_data[0x1d] == ip_host[3]) {

                            //                            qDebug() << "Modify one host!";
                            uchar* new_pkt = modify_packet((uchar*)pkt_data, header->caplen);
                            pkt_data = new_pkt;

                        }
                }
                else {
                    //                    qDebug() << "Modify all!";
                    uchar* new_pkt = modify_packet((uchar*)pkt_data, header->caplen);
                    pkt_data = new_pkt;
                }


                /* ============================== */

                qDebug() << ">> Len: " << header->caplen << "ID: " << hex << pkt_data[0x12] << pkt_data[0x13] << dec;
            }
            else {
                qDebug("<< Len: %u\n", header->caplen);
            }

            /* === WINDOWS === */
            /* LeaveCriticalSection(&print_cs); */
            g_mutex.unlock();


            /*
             * Send the just received packet to the output adaper
             */

            if(pcap_sendpacket(ad_couple->output_adapter, pkt_data, header->caplen) != 0)
            {
                /* === WINDOWS === */
                /* EnterCriticalSection(&print_cs); */
                g_mutex.lock();

                QString msg = "Error sending a ";
                msg += QString::number(header->caplen) + " bytes packets on interface " + QString::number(ad_couple->state);
                msg += "\nError: ";
                msg += pcap_geterr(ad_couple->output_adapter);
                QMessageBox::critical(nullptr, "Error Capturing!", msg);


                /* === WINDOWS === */
                /* LeaveCriticalSection(&print_cs); */
                g_mutex.unlock();
            }
            else
            {
                n_fwd++;
            }


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


        qDebug() << "Error capturing the packets: " << pcap_geterr(ad_couple->input_adapter);

        /* === WINDOWS === */
        /* LeaveCriticalSection(&print_cs); */
        g_mutex.unlock();
    }
    else
    {
        /* === WINDOWS === */
        /* EnterCriticalSection(&print_cs); */
        g_mutex.lock();

        qDebug() << "End of bridging on interface: " << ad_couple->state;
        qDebug() << "\tForwarded packets: " << n_fwd;

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
    qDebug() << "Exit!";
    kill_forwaders = 1;
    //    sleep(2000);

    //    WaitForMultipleObjects(2,
    //                           threads,
    //                           TRUE,		/* Wait for all the handles */
    //                           5000);		/* Timeout */
    //    exit(0);

}

uchar* modify_packet(uchar* buffer, uint &size)
{
    /* Check that packet has IP */
    if (buffer[0x0c] == 0x08 && buffer[0x0d] == 0x00) {
        ushort ip_size = (uint)((buffer[0x10] << 8) & 0xff00 ) | (buffer[0x11] & 0x00ff);

        /* -- HERE CHANGE IP parametres! -- */
        uchar start_ip = 0x0e;
        uchar *ip_header = buffer + start_ip; // START of IP HEADER in packet

        /* -- DF bit -- */
        /* This param depends on TCP flags,
           so it will change in tcp too, but now it is set
         */
        ip_header[6] = ((ip_header[6]) & 0b10111111) | 0b01000000; // set

        /* -- TTL -- */
        ip_header[8] = ttl; /* Linux ttl */

        /* -- IP checksum -- */
        /* This param will re-count after TCP check,
                                                 * because IP DF-bit maybe will changed there
                                                 */

        /* Check next protocol */
        /* -- TCP -- */
        if (buffer[0x17] == 0x06)
        {
            ushort tcp_len = ip_size - (buffer[0x0e]  & 0b00001111) * 4;
            //            qDebug()<< "tcp: " << tcp_len;
            ushort pseudo_len = tcp_len + 12;
            //            qDebug()<< "pseudo: " << pseudo_len;

            /* -- HERE CHANGE TCP parametres! -- */
            uchar start_tcp = 0x22;  // START of TCP HEADER in packet
            uchar* tcp_header = buffer + start_tcp;

            /* -- Window size -- */
            /* This param also depends on TCP Options,
                                                     * so it will changed later
                                                     */

            /* Get header tcp size (4 bits * 4 bytes)*/
            uchar tcp_hdr_size = ((tcp_header[0x0c] >> 4) & 0x0f) * 4;
            //            qDebug()<< "hdr_size: " << dec << (uint)tcp_hdr_size << hex;

            ushort tcp_flags = ((tcp_header[0x0c] << 8) & 0xff00)
                    | (tcp_header[0x0d] & 0x00ff);

            //            qDebug()<< hex << "flags: R  NCEUAPRSF\n";
            //                           0b0000000000000001  - FIN
            //                           0b0000000000000010  - SYN
            //                           0b0000000000010000  - ACK
            //                           0b0000000000010001  - SYN,ACK

            //            qDebug() << "       " << QString::number(tcp_flags, 2);

            /* Check if there are any TCP-OPTIONS */
            if (tcp_hdr_size > 20) {
                /* -- modify OPTIONS -- */

                uchar tcp_options_size = tcp_hdr_size - 20;
                /* NOTE! max len of options - 20 bytes */

                uchar new_options_size;
                /* check SYN flag */
                /* ------------- LEN |R  NCEUAPRSF ---- */
                if ((tcp_flags & 0b0000000000000010) == 0b0000000000000010) {
                    //                if (false) {
                    qDebug()<< "SYN!";
                    /* -- Recheck IP DF-bit -- */
                    if (syn_df_bit)
                        ip_header[6] = ((ip_header[6]) & 0b10111111) | 0b01000000;
                    else
                        ip_header[6] = ((ip_header[6]) & 0b10111111);

                    /* -- Window size -- */
                    tcp_header[0x0e] = (syn_win_size >> 8) & 0x00ff;
                    tcp_header[0x0f] = syn_win_size & 0x00ff;

                    /* -- TCP Options change -- */
                    new_options_size = syn_options.size();
                    memcpy(tcp_header + 20, &syn_options[0], new_options_size);
                }

                /* check SYN,ACK flag */
                if ((tcp_flags & 0b0000000000010010) == 0b0000000000010010) {
                    //                if (false) {
                    qDebug()<< "SYN-ACK!";
                    /* -- Recheck IP DF-bit -- */
                    if (syn_ack_df_bit)
                        ip_header[6] = ((ip_header[6]) & 0b10111111) | 0b01000000;
                    else
                        ip_header[6] = ((ip_header[6]) & 0b10111111);

                    /* -- Window size -- */
                    tcp_header[0x0e] = (syn_ack_win_size >> 8) & 0x00ff;
                    tcp_header[0x0f] = syn_ack_win_size & 0x00ff;

                    /* -- TCP Options change -- */
                    new_options_size = syn_ack_options.size();
                    memcpy(tcp_header + 20, &syn_ack_options[0], new_options_size);
                }
                qDebug()<< "new opt size: " << (uint)new_options_size;
                size = ip_size + 14 - (tcp_options_size) + new_options_size;

                /* Change TCP size */
                short delta = new_options_size -  tcp_options_size;
                tcp_hdr_size += (char)delta;
                tcp_hdr_size /= 4;
                if (tcp_hdr_size < 0x0f) {
                    buffer[0x2e] = buffer[0x2e] & 0x0f;
                    buffer[0x2e] = buffer[0x2e] | ((tcp_hdr_size << 4) & 0xf0);
                }

                //                /* Change Packet size */
                //                size += delta;

                /* Change IP size */
                ip_size += new_options_size -  tcp_options_size;
                buffer[0x10] = ip_size & 0xff00;
                buffer[0x11] = ip_size & 0x00ff;
            }
            /* -- TCP end -- */

            /* -- HTTP -- */
            else {

                int len_template = strlen("User-Agent: ");
                char user_agent[] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36 OPR/67.0.3575.137";
                int len_user_agent = strlen(user_agent);

                char *temp = new char[10];
                strncpy(temp, (char*)(buffer + 0x36), 10);
                qDebug() << "HTTP?:   " << temp;

                if (strcmp(temp, "GET / HTTP") == 0) {
                    qDebug() << "TRUE!!!";
                    char *http_start = (char*)(buffer + 0x36);


                    /* Search pos of start/end User-agent */
                    char* start_agent = strstr(http_start, "User-Agent: ");
                    start_agent += len_template;
                    char* end_agent = strstr(start_agent, "\r\n");

                    //                    strncpy(temp, start_agent, 10);
                    //                    qDebug() << "U/Ag?: " << temp;

                    int size_begin = start_agent - (char*)buffer - 12;
                    int size_middle = end_agent - start_agent;
                    qDebug() << "IP_SIZE = " << ip_size;
                    int size_end = ip_size - size_begin- size_middle;

                    /* Insert new User-agent */
                    uchar* temp_buf = new uchar [size_end];
                    //                    strncpy(temp_buf, (char*)buffer, start_agent - (char*)buffer);

                    qDebug() << "======== OLD =============\n" << http_start;

                    //                    strcpy(temp_buf, end_agent);

                    qDebug() << "Start    = " << size_begin;
                    qDebug() << "Middle   = " << size_middle;
                    qDebug() << "Size end = " << size_end;
                    qDebug() << "Sum      = " << size_begin + size_middle + size_end;

                    memcpy(temp_buf, end_agent, size_end);
                    memcpy(start_agent, user_agent, len_user_agent);
                    memcpy(start_agent + len_user_agent, temp_buf, size_end);

                    //                    strncpy((char*)temp_buf, end_agent, size_end);
                    //                    strncpy(start_agent, user_agent, len_user_agent);
                    //                    strncpy(start_agent + len_user_agent, (char*)temp_buf, size_end);
                    buffer[size_begin + len_template + len_user_agent + size_end] = 0x0d;
                    buffer[size_begin + len_template + len_user_agent + size_end + 1] = 0x0a;
                    size += len_user_agent - size_middle;

                    buffer[size] = '\0';

                    /* Change IP size */
                    ip_size += len_user_agent - size_middle;
                    buffer[0x10] = (ip_size & 0xff00) >> 8;
                    buffer[0x11] = ip_size & 0x00ff;


                    /* Change packet len */
                    qDebug() << "======== NEW =============\n" << http_start;

                    //                    size -= 10;
                    qDebug() << "NEW SIZE    = " << size;
                    delete[] temp_buf;
                    delete[] temp;
                }


                //                delete[] temp;
            }
            /* -- HTTP end -- */

        }
        else
            /* -- ICMP -- */
            if (buffer[0x17]  == 0x01) {

                /* -- ICMP  end -- */
            }

        /* TCP checksum */
        ushort sum = tcp_sum(buffer, ip_size - (buffer[0x0e]  & 0b00001111) * 4);
        buffer[0x32] = (uchar)((sum & 0xff00) >> 8);
        buffer[0x33] = (uchar) (sum & 0x00ff);

        /* -- IP checksum -- */
        /* This param will re-count after TCP check,
         * because IP DF-bit maybe will changed there
         */

        //        unsigned short sum;
        sum = ip_sum(buffer);
        buffer[24] = (unsigned char)((sum & 0xff00) >> 8);
        buffer[25] = (unsigned char) (sum & 0x00ff);
        /* -- IP end -- */

        if (buffer[0x17]  == 0x01) {

            /* -- ICMP -- */
            /* -- ICMP  end -- */
            sum = icmp_sum(buffer);
            buffer[0x24] = (uchar)((sum & 0xff00) >> 8);
            buffer[0x25] = (uchar) (sum & 0x00ff);
            qDebug() << "ICMP = " << hex << sum;
        }
    }

    return buffer;
}


/* My checksum */
ushort tcp_sum(uchar *buffer, ushort tcp_len)
{
    uint sum = 0;
    uchar start = 0x22;  // START of TCP HEADER in packet
    uchar* tcp_header = buffer + start;

    /* -- Pseudo TCP header -- */
    // Add source
    sum += ((buffer[0x1a] << 8) & 0xff00) | (buffer[0x1b] & 0x00ff);
    sum += ((buffer[0x1c] << 8) & 0xff00) | (buffer[0x1d] & 0x00ff);

    // Add destination to sum
    sum += ((buffer[0x1e] << 8) & 0xff00) | (buffer[0x1f]& 0x00ff);
    sum += ((buffer[0x20] << 8) & 0xff00) | (buffer[0x21]& 0x00ff);

    sum += 0x0006; // RESERVED + PROTOCOL
    sum += tcp_len;

    /* -- TCP + PAYLOAD -- */
    for (ushort i = 0; i < tcp_len - 2; i += 2)
        sum += ((tcp_header[i] << 8) & 0xff00)
                | (tcp_header[i + 1] & 0x00ff);
    if (tcp_len % 2 == 0)
        sum += ((tcp_header[tcp_len - 2] << 8) & 0xff00)
                | (tcp_header[tcp_len - 2 + 1] & 0x00ff);
    else
        sum += ((tcp_header[tcp_len - 2] << 8) & 0xff00);

    // Simple sub the current checksum that was already add
    sum -= ((tcp_header[16] << 8) & 0xff00)
            | (tcp_header[17] & 0x00ff);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (~sum);
}

ushort ip_sum (uchar *buffer)
{
    uchar start = 0x0e;
    uchar *ip_header = buffer + start; // START of IP HEADER in packet
    uint sum = 0;
    uchar ip_size = (*ip_header & 0b00001111) * 4;
    for (ushort i = 0; i < ip_size; i += 2)
        sum += ((ip_header[i] << 8) & 0xff00)
                | (ip_header[i + 1] & 0x00ff);

    // Simple sub the current checksum that was already add
    sum -= ((ip_header[10] << 8) & 0xff00) | (ip_header[11] & 0x00ff);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}
ushort icmp_sum(uchar *buffer)
{
    uchar start = 0x22;
    uchar *icmp_header = buffer + start; // START of ICMP HEADER in packet
    uint sum = 0;
    ushort icmp_size = ((buffer[0x10] << 8) & 0xff00 ) | (buffer[0x11] & 0x00ff);
    icmp_size -= (buffer[0x0e] & 0b00001111) * 4;
    for (ushort i = 0; i < icmp_size; i += 2)
        sum += ((icmp_header[i] << 8) & 0xff00)
                | (icmp_header[i + 1] & 0x00ff);

    // Simple sub the current checksum that was already add
    sum -= ((icmp_header[2] << 8) & 0xff00) | (icmp_header[3] & 0x00ff);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

void get_os_params(os_sig os, bool type_param, ushort &win_size,
                   uchar &ttl, uchar &df_bit, std::vector<uchar> &options)
{
    options.clear();
    QString temp;
    if (type_param == 0)
        temp = os.s_params;
    else
        temp = os.sa_params;
    QStringList params = temp.split(":");

    win_size = params.at(0).toUShort(nullptr, 10);
    ttl = params.at(1).toUShort(nullptr, 10);
    df_bit = params.at(2).toUShort(nullptr, 10);
    ushort options_size = params.at(3).toUShort(nullptr, 10);

    /* forming TCP options */
    temp = params.at(4);
    params = temp.split(",");
    foreach (QString param, params) {
        ushort val = 0;
        if (param.length() > 1) {
            QRegularExpression re("\\d+");
            QRegularExpressionMatch match = re.match(param);
            val = match.captured(0).toUShort();
        }
        switch (param.at(0).unicode())
        {
        case short('M'):
        {
            options.push_back(0x02);
            options.push_back(0x04);
            options.push_back((val >> 8) & 0x00ff);
            options.push_back(val & 0x00ff);
            break;
        }
        case short('W'):
        {
            options.push_back(0x03);
            options.push_back(0x03);
            options.push_back(val & 0x00ff);
            break;
        }
        case short('T'):
        {
            options.push_back(0x08);
            options.push_back(0x0a);
            options.insert(options.end(), 2, 0x00);
            options.push_back(0xe2);
            options.push_back(0x40);
            options.insert(options.end(), 4, 0xff);
            break;
        }
        case short('N'):
        {
            options.push_back(0x01);
            break;
        }
        case short('E'):
        {
            options.push_back(0x00);
            options.push_back(0x00);
            break;
        }
        case short('S'):
            options.push_back(0x04);
            options.push_back(0x02);
            break;
        }
    }

    //    qDebug() << "HERE = " << hex << options;
    if (options.size() != options_size - 40)
        QMessageBox::critical(nullptr, "Error", QString("Error size options!\n%1\n%2").arg(QString::number(options.size()), QString::number(options_size -  40)));
}

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

