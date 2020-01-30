#include "mw.h"
#include "ui_mw.h"
#include "QDebug"
#include "bridge.cpp"

mw::mw(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::mw)
{
    ui->setupUi(this);
    get_ip_src(2);
    ui->gbox_param->setEnabled(false);
    
    connect(ui->rb_auto, SIGNAL(clicked()), this, SLOT(click_auto()));
    connect(ui->rb_semi, SIGNAL(clicked()), this, SLOT(click_semi()));
    connect(ui->rb_manual, SIGNAL(clicked()), this, SLOT(click_manual()));
    //    connect(ui->cb_ttl, SIGNAL(stateChanged()), this, SLOT(click_ttl()));
    //    connect(ui->cb_ip, SIGNAL(stateChanged()), this, SLOT(click_ip_dst()));
    //    connect(ui->cb_ip, SIGNAL(stateChanged()), this, SLOT(click_ip_src()));
    
    connect(ui->pb_capture, SIGNAL(clicked()), this, SLOT(start_capturing()));
    connect(ui->pb_exit, SIGNAL(clicked()), this, SLOT(exit_capture()));
    
    /* Chosing adapters */
    QStringList devs = get_all_devs();
    ui->comb_adapter_1->addItems(devs);
    ui->comb_adapter_2->addItems(devs);
/*
    u_char* packet;
    u_int size;
    size = 20;
    manual_wind *wind = new manual_wind(packet, &size);
    wind->show();
    */
}

mw::~mw()
{
    delete ui;
}

void mw::click_auto()
{
    ui->gbox_param->setEnabled(false);
    _auto = true;
    _semi = false;
    _manual = false;
}


void mw::click_semi()
{
    ui->gbox_param->setEnabled(true);
    
    _auto = false;
    _semi = true;
    _manual = false;
    
    //    click_ttl();
    //    click_ip_dst();
    //    click_ip_src();
    
}

void mw::click_manual()
{
    ui->gbox_param->setEnabled(false);
    
    _auto = false;
    _semi = false;
    _manual = true;
}


void mw::click_ttl()
{
    qDebug() << "Click ttl!";
    if (ui->cb_ttl->isChecked()){
        ui->sp_ttl_old->setEnabled(true);
        ui->sp_ttl_new->setEnabled(true);
    } else {
        ui->sp_ttl_old->setEnabled(false);
        ui->sp_ttl_new->setEnabled(false);
    }
}

void mw::click_ip_dst()
{
    if (ui->cb_ip_dst->isChecked()) {

        
        ui->sp_ip_dst_new_1->setEnabled(true);
        ui->sp_ip_dst_new_2->setEnabled(true);
        ui->sp_ip_dst_new_3->setEnabled(true);
        ui->sp_ip_dst_new_4->setEnabled(true);
        
        ui->sp_ip_dst_old_1->setEnabled(true);
        ui->sp_ip_dst_old_2->setEnabled(true);
        ui->sp_ip_dst_old_3->setEnabled(true);
        ui->sp_ip_dst_old_4->setEnabled(true);
        
        ui->dot_7->setEnabled(true);
        ui->dot_8->setEnabled(true);
        ui->dot_9->setEnabled(true);
        ui->dot_10->setEnabled(true);
        ui->dot_11->setEnabled(true);
        ui->dot_12->setEnabled(true);
    } else {
        ui->sp_ip_dst_new_1->setEnabled(false);
        ui->sp_ip_dst_new_2->setEnabled(false);
        ui->sp_ip_dst_new_3->setEnabled(false);
        ui->sp_ip_dst_new_4->setEnabled(false);
        
        ui->sp_ip_dst_old_1->setEnabled(false);
        ui->sp_ip_dst_old_2->setEnabled(false);
        ui->sp_ip_dst_old_3->setEnabled(false);
        ui->sp_ip_dst_old_4->setEnabled(false);
        
        ui->dot_7->setEnabled(false);
        ui->dot_8->setEnabled(false);
        ui->dot_9->setEnabled(false);
        ui->dot_10->setEnabled(false);
        ui->dot_11->setEnabled(false);
        ui->dot_12->setEnabled(false);
    }
}
void mw::click_ip_src()
{
    if (ui->cb_ip_src->isChecked()) {
        ui->sp_ip_src_new_1->setEnabled(true);
        ui->sp_ip_src_new_2->setEnabled(true);
        ui->sp_ip_src_new_3->setEnabled(true);
        ui->sp_ip_src_new_4->setEnabled(true);

        ui->sp_ip_src_old_1->setEnabled(true);
        ui->sp_ip_src_old_2->setEnabled(true);
        ui->sp_ip_src_old_3->setEnabled(true);
        ui->sp_ip_src_old_4->setEnabled(true);

        ui->dot_1->setEnabled(true);
        ui->dot_2->setEnabled(true);
        ui->dot_3->setEnabled(true);
        ui->dot_4->setEnabled(true);
        ui->dot_5->setEnabled(true);
        ui->dot_6->setEnabled(true);
    } else {
        ui->sp_ip_src_new_1->setEnabled(false);
        ui->sp_ip_src_new_2->setEnabled(false);
        ui->sp_ip_src_new_3->setEnabled(false);
        ui->sp_ip_src_new_4->setEnabled(false);

        ui->sp_ip_src_old_1->setEnabled(false);
        ui->sp_ip_src_old_2->setEnabled(false);
        ui->sp_ip_src_old_3->setEnabled(false);
        ui->sp_ip_src_old_4->setEnabled(false);

        ui->dot_1->setEnabled(false);
        ui->dot_2->setEnabled(false);
        ui->dot_3->setEnabled(false);
        ui->dot_4->setEnabled(false);
        ui->dot_5->setEnabled(false);
        ui->dot_6->setEnabled(false);
    }
}

void mw::exit_capture()
{
    
    ctrlc_handler(1);
    exit(0);
    this->close();
}


int mw::get_num_dev_1() { return ui->comb_adapter_1->currentIndex() + 1; }
int mw::get_num_dev_2() { return ui->comb_adapter_2->currentIndex() + 1; }

int mw::get_ttl(int num)
{
    if (num == 1)
        return ui->sp_ttl_old->value();
    if (num == 2)
        return ui->sp_ttl_old->value();
    else
        return -1;
}


std::vector<int> mw::get_ip_dst(int type)
{
    // old
    if (type == 1) {
        std::vector<int> temp;
        temp.push_back(ui->sp_ip_dst_old_1->value());
        temp.push_back(ui->sp_ip_dst_old_2->value());
        temp.push_back(ui->sp_ip_dst_old_3->value());
        temp.push_back(ui->sp_ip_dst_old_4->value());
        qDebug() << temp;
        return temp;
    }
    // new
    if (type == 2) {
        std::vector<int> temp;
        temp.push_back(ui->sp_ip_dst_new_1->value());
        temp.push_back(ui->sp_ip_dst_new_2->value());
        temp.push_back(ui->sp_ip_dst_new_3->value());
        temp.push_back(ui->sp_ip_dst_new_4->value());
        qDebug() << temp;
        return temp;
    }
}

std::vector<int> mw::get_ip_src(int type)
{
    // old
    if (type == 1) {
        std::vector<int> temp;
        temp.push_back(ui->sp_ip_src_old_1->value());
        temp.push_back(ui->sp_ip_src_old_2->value());
        temp.push_back(ui->sp_ip_src_old_3->value());
        temp.push_back(ui->sp_ip_src_old_4->value());
        qDebug() << temp;
        return temp;
    }
    // new
    if (type == 2) {
        std::vector<int> temp;
        temp.push_back(ui->sp_ip_src_new_1->value());
        temp.push_back(ui->sp_ip_src_new_2->value());
        temp.push_back(ui->sp_ip_src_new_3->value());
        temp.push_back(ui->sp_ip_src_new_4->value());
        qDebug() << temp;
        return temp;
    }
}
