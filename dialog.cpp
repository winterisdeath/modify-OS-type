#include "dialog.h"
#include "ui_dialog.h"

dialog::dialog(int &value, bool &check, QString title, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::dialog)
{
    ui->setupUi(this);
    this->setWindowTitle(title);
    this->setFixedSize(this->width(), this->height());
}

dialog::~dialog()
{
    delete ui;
}


void dialog::on_pb_ok_clicked()
{
    int value = ui->sp_box->value();
    emit ret_signal(value);
    this->close();
}

void dialog::on_pb_canc_clicked()
{
    emit ret_signal(-1);
    this->close();
}

