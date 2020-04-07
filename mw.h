#ifndef MW_H
#define MW_H

#include <QMainWindow>
#include <QDir>
#include <QDebug>
#include <QDomDocument>
#include <QFile>
#include <QMessageBox>
#include <QList>



#include "tcp_opt.h"


#include "packets_headers.h"

QT_BEGIN_NAMESPACE
namespace Ui { class mw; }
QT_END_NAMESPACE


/* Storage data structure used to pass parameters to the threads */
struct in_out_adapter
{
    unsigned int state;		/* Some simple state information */
    pcap_t *input_adapter;
    pcap_t *output_adapter;
};

class mw : public QMainWindow
{
    Q_OBJECT



private:
    Ui::mw *ui;
    tcp_opt *tcp_opt_widget = new tcp_opt;
    int delta = tcp_opt_widget->height();
    int old_height;

public:
    mw(QWidget *parent = nullptr);
    ~mw();

    int get_num_dev_1();
    int get_num_dev_2();

    std::vector<int> get_ip_host();
    pcap_t *adhandle1, *adhandle2;
    pcap_if_t *alldevs;
    struct bpf_program fcode;
    in_out_adapter couple1, couple2;
    QList<os_sig> os_list;

private slots:
    void host_one();
    void host_all();
    int  start_capturing();
    void exit_capture();

    /* SLOT for changing tab */
    void change_tab(int current_tab);

    /* SLOT for open and refresh DB view */
    void open_fp_database();
};
#endif // MW_H
