#include "mw.h"
#include "ui_mw.h"
#include "bridge.cpp"
#include <QCheckBox>

mw::mw(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::mw)
{
    ui->setupUi(this);


    connect(ui->rb_host_all, SIGNAL(clicked()), this, SLOT(host_all()));
    connect(ui->rb_host_one, SIGNAL(clicked()), this, SLOT(host_one()));

    connect(ui->pb_capture, SIGNAL(clicked()), this, SLOT(start_capturing()));
    connect(ui->pb_exit, SIGNAL(clicked()), this, SLOT(exit_capture()));

    /* SLOTS for changing tabs */
    connect(ui->tabWidget, SIGNAL(currentChanged(int)), this, SLOT(change_tab(int)));

    /* SLOT for refresh FP database */
    //        connect(new_wind, SIGNAL(ret_signal(int)), this, SLOT(new_func(int)));
    connect(tcp_opt_widget, SIGNAL(refresh_signal()), this, SLOT(open_fp_database()));

    /* Chosing adapters */
    QStringList devs = get_all_devs();
    ui->comb_adapter_1->addItems(devs);
    ui->comb_adapter_2->addItems(devs);
    if (ui->comb_adapter_1->currentText() == ui->comb_adapter_2->currentText()
            && devs.size() > 1)
        ui->comb_adapter_2->setCurrentIndex(ui->comb_adapter_2->currentIndex() + 1);

    connect(ui->rb_host_all, SIGNAL(clicked()), this, SLOT(host_all()));
    connect(ui->rb_host_one, SIGNAL(clicked()), this, SLOT(host_one()));

    /* get info from fingerprint database */
    open_fp_database();

    /* select protection of all hosts */
    ui->rb_host_all->click();

    /* Add manual mod */
    ui->tabWidget->addTab(tcp_opt_widget, "Manual");


    this->setFixedSize(this->size());
}

mw::~mw()
{
    pcap_close(adhandle1);
    pcap_close(adhandle2);
    pcap_freealldevs(alldevs);
    delete ui;
}

void mw::open_fp_database()
{
    os_list.clear();

    QString fname;
    fname = "/home/snow/C++/tcp_small.xml";
    if (fname.isEmpty()){
        QMessageBox::critical(this, QString("Error"), QString("Path to file is emtry!"));
        exit(-1);
    }

    QFile file(fname);
    file.open(QIODevice::ReadOnly);

    if (!file.isOpen()) {
        QMessageBox::critical(this, QString("Error"), QString("File not opened!"));
        exit(-1);
    }

    QDomDocument xml;
    if (!xml.setContent(&file)) {
        QMessageBox::critical(this, QString("Error"), QString("Can't read xml!"));
        exit(-1);
    }

    QDomElement elem;
    elem = xml.documentElement();
    qDebug() << " ---" << elem.tagName();

    if (elem.tagName() == "fingerprints") {
        for (QDomElement temp = xml.documentElement().firstChildElement();
             !temp.isNull(); temp = temp.nextSiblingElement("fingerprint"))
        {
            os_sig os;
            QDomElement elem = temp;
            /* Getting attributes (name/class) of OS fingerprint */
            os.os_name = elem.attribute("os_name");
            os.os_class = elem.attribute("os_class");

            /* Getting signature of current OS fingerprint */
            elem = elem.firstChildElement(); // tcp_test
            QDomElement sig = elem.firstChildElement("SA");
            os.sa_params = sig.attribute("tcpsig");
            sig = elem.firstChildElement("S");
            os.s_params = sig.attribute("tcpsig");

            os_list.push_back(os);
            //            qDebug() << os.os_name << " " <<  os.os_class;
            //            qDebug() << "\t" << os.s_params << " " <<  os.sa_params;
        }
    }

    /* Set OS names (class) to GUI */
    QStringList temp_os_name;
    foreach (os_sig os, os_list)
        temp_os_name.push_back(os.os_name + " (" + os.os_class + ")");
    ui->cb_os_type->clear();
    ui->cb_os_type->addItems(temp_os_name);

}

void mw::change_tab(int current_tab)
{
    //    QMessageBox::critical(NULL, "Title", QString::number(current_tab));
    if (current_tab == 1) {
        old_height = ui->tabWidget->height();
        setFixedSize(width(), height() + delta - old_height);
        ui->tabWidget->resize(ui->tabWidget->width(), delta);
        //        ui->label_2->move(ui->label_2->x(), ui->label_2->y() + delta);
        //        ui->label_3->move(ui->label_3->x(), ui->label_3->y() + delta);
        //        ui->label_6->move(ui->label_6->x(), ui->label_6->y() + delta);
        //        ui->label_7->move(ui->label_7->x(), ui->label_7->y() + delta);

        ui->groupBox->move(ui->groupBox->x(), ui->groupBox->y() + delta - old_height);
        ui->groupBox_2->move(ui->groupBox_2->x(), ui->groupBox_2->y() + delta - old_height);
        ui->pb_capture->move(ui->pb_capture->x(), ui->pb_capture->y() + delta - old_height);
        ui->pb_exit->move(ui->pb_exit->x(), ui->pb_exit->y() + delta - old_height);

    }
    else if (current_tab == 0) {
        setFixedSize(width(), height() - delta + old_height);
        ui->tabWidget->resize(ui->tabWidget->width(), old_height);
        ui->groupBox->move(ui->groupBox->x(), ui->groupBox->y() - delta + old_height);
        ui->groupBox_2->move(ui->groupBox_2->x(), ui->groupBox_2->y() - delta + old_height);
        ui->pb_capture->move(ui->pb_capture->x(), ui->pb_capture->y() - delta + old_height);
        ui->pb_exit->move(ui->pb_exit->x(), ui->pb_exit->y() - delta + old_height);
    }

}

void mw::exit_capture()
{
    ctrlc_handler(1);
    sleep(1);
    exit(0);
}


int mw::get_num_dev_1() { return ui->comb_adapter_1->currentIndex() + 1; }
int mw::get_num_dev_2() { return ui->comb_adapter_2->currentIndex() + 1; }



std::vector<int> mw::get_ip_host()
{
    std::vector<int> temp;
    temp.push_back(ui->sp_ip_1->value());
    temp.push_back(ui->sp_ip_2->value());
    temp.push_back(ui->sp_ip_3->value());
    temp.push_back(ui->sp_ip_4->value());

    return temp;
}


void mw::host_one()
{
    ui->lb_dot_1->setEnabled(true);
    ui->lb_dot_2->setEnabled(true);
    ui->lb_dot_3->setEnabled(true);

    ui->sp_ip_1->setEnabled(true);
    ui->sp_ip_2->setEnabled(true);
    ui->sp_ip_3->setEnabled(true);
    ui->sp_ip_4->setEnabled(true);
}

void mw::host_all()
{

    ui->lb_dot_1->setEnabled(false);
    ui->lb_dot_2->setEnabled(false);
    ui->lb_dot_3->setEnabled(false);

    ui->sp_ip_1->setEnabled(false);
    ui->sp_ip_2->setEnabled(false);
    ui->sp_ip_3->setEnabled(false);
    ui->sp_ip_4->setEnabled(false);
}
