#include "manual_wind.h"
#include "ui_manual_wind.h"
#include <QDebug>
#include <cstring>

manual_wind::manual_wind(u_char* packet, u_int *size, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::manual_wind)
{
    ui->setupUi(this);
    int num_cols = 16;
    int num_rows = (*size)/num_cols + 1 ;
    ui->tb->setRowCount(num_rows);
    ui->tb->setColumnCount(num_cols);

    int val = 0x0000;
    for (int row = 0; row < ui->tb->columnCount(); ++row) {
        QString temp = QString::number(val, 16);
        if (temp.length() == 1)
            temp = "000" + temp;
        if (temp.length() == 2)
            temp = "00" + temp;
        if (temp.length() == 3)
            temp = "0" + temp;
        QTableWidgetItem *item = new QTableWidgetItem(temp);
        val += 16;
        ui->tb->setVerticalHeaderItem(row, item);
    }

    //  table initialization
    for (int row = 0; row < ui->tb->rowCount(); ++row) {
        for (int col =0; col < ui->tb->columnCount(); ++col) {
            QTableWidgetItem *item;
            if (row * 16 + col < (*size)) {
                QString temp;
                temp = QString::number((int)packet[row * 16 + col], 16);
                item = new QTableWidgetItem(temp);
            }
            else
                item = new QTableWidgetItem();
            ui->tb->setItem(row,col, item);
        }
    }

    for (int col = 0; col < ui->tb->columnCount(); ++col) {
        ui->tb->setColumnWidth(col, 30);
    }
    for (int row = 0; row < ui->tb->rowCount(); ++row) {
        ui->tb->setRowHeight(row, 30);
    }

    ui->tb->resize((ui->tb->columnCount() + 1) * 30 + ui->tb->verticalHeader()->width(),
                   (ui->tb->rowCount()) * 30 + ui->tb->horizontalHeader()->height() + 5);

    resize(ui->tb->x() + ui->tb->width() + 5,
           ui->tb->y() + ui->tb->height() + 5);
}

manual_wind::~manual_wind()
{
    delete ui;
}

void manual_wind::on_pushButton_clicked()
{
    end_modify = true;
    u_char *packet = new u_char[200];
    u_int size = 0;
    unsigned int *new_size;
    get_packet(packet, size);

    qDebug() << "end " ;
    new_size = &size;

    qDebug() << "new_s: " << (*new_size);
    for (int i = 0; i < *new_size; i++)
        qDebug() << hex <<  packet[i];

}

void manual_wind::get_packet(u_char *packet, u_int& size)
{
    unsigned int _size;
    _size = ui->tb->columnCount() * ui->tb->rowCount();
    qDebug() << "size: "<< _size; // if delete it, all will crash

    unsigned char *temp = new unsigned char[_size];
    int cnt = 0;
    QString str, all;
    for (int row = 0; row < ui->tb->rowCount(); ++row) {
        for (int col =0; col < ui->tb->columnCount(); ++col) {
            str = ui->tb->item(row, col)->text();
            if (str.isEmpty())
                break;
            if (cnt < _size) {
                all += str.toStdString().c_str();
                bool *check;
                unsigned char t = (str.toUInt(check, 16) & 0x000000ff);
                temp[cnt] = (unsigned char)t;
            }
            cnt++;
        }
    }

    /*
    qDebug() << temp << all;
    for (int i = 0; i < cnt; i++)
        qDebug() << hex <<  temp[i];
    */

    memcpy(packet, temp, cnt );
    size = cnt;
}

void manual_wind::on_pb_drop_clicked()
{
    drop = true;
}
