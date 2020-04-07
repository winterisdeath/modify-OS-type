#include "tcp_opt.h"
#include "ui_tcp_opt.h"
#include <QDebug>

tcp_opt::tcp_opt(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::tcp_opt)
{
    ui->setupUi(this);

    connect(ui->pb_add,         SIGNAL(clicked()), this, SLOT(push_add()));
    connect(ui->pb_del,         SIGNAL(clicked()), this, SLOT(push_del()));
    connect(ui->pb_ins,         SIGNAL(clicked()), this, SLOT(push_ins()));
    connect(ui->pb_move_up,     SIGNAL(clicked()), this, SLOT(move_up()));
    connect(ui->pb_move_down,   SIGNAL(clicked()), this, SLOT(move_down()));

    connect(ui->pb_gen_sa_sig,  SIGNAL(clicked()), this, SLOT(write_sa_sig()));
    connect(ui->pb_gen_s_sig,   SIGNAL(clicked()), this, SLOT(write_s_sig()));

    ui->list_all->setCurrentRow(0);
    ui->lb_sa_val->clear();
    ui->lb_s_val->clear();
}

tcp_opt::~tcp_opt()
{
    delete ui;
}

int tcp_opt::input_val(QString title)
{
    dialog *new_wind = new dialog(_value, _check, "Input " + title, this);
    connect(new_wind, SIGNAL(ret_signal(int)), this, SLOT(new_func(int)));
    new_wind->show();
    new_wind->raise();
    new_wind->activateWindow();
    new_wind->exec();

    return _ret_val;
}

void tcp_opt::new_func(int val)
{
    _ret_val = val;
}

QString tcp_opt::gen_sig()
{
    QString sig;
    // window size
    sig += QString::number(ui->sp_win_size->value());
    sig += ":";

    // ttl
    sig += QString::number(ui->sp_ttl->value());
    sig += ":";

    // DF bit
    sig += QString::number(ui->sp_df_bit->value());
    sig += ":";

    // Count len of options
    QStringList list;

    int cnt = ui->list_new->count() - 1;
    if (cnt >= 0) {
        for (int i = 0; i < cnt; ++i) {
            QString temp  = ui->list_new->item(i)->text();
            temp.remove(QRegularExpression("(:|S:|SS|OL|OP|ACK)"));
            list.append(temp);
        }

        QString temp  = ui->list_new->item(cnt)->text();
        temp.remove(QRegularExpression("(:|S:|SS|OL|OP|ACK)"));
        list.append(temp);
    }

    short size = 0;
    foreach(QString item,  list) {
        switch(item.at(0).unicode())
        {
        case short('M'):
            size += 4;
            break;

        case short('W'):
            size += 3;
            break;

        case short('T'):
            size += 10;
            break;

        case short('N'):
            size += 1;
            break;

        case short('E'):
            size += 2;
            break;

        case short('S'):
            size += 2;
            break;
        }
    }

    sig += QString::number(size);
    sig += ":";


    foreach(QString item,  list) {
        sig += item;
        sig += ",";
    }
    sig.resize(sig.size() - 1);

    return  sig;
}

void tcp_opt::write_sa_sig()
{
    sa_sig.clear();
    sa_sig.append(gen_sig());
    ui->lb_sa_val->setText(sa_sig);
}

void tcp_opt::write_s_sig()
{
    s_sig.clear();
    s_sig.append(gen_sig());
    ui->lb_s_val->setText(s_sig);
}

void tcp_opt::push_add()
{
    QString item_text = ui->list_all->currentItem()->text();

    switch(ui->list_all->currentRow()) {
    case 2:     // MSS
        item_text = "MSS";
        item_text += ":" + QString::number(input_val(item_text));
        break;

    case 3:    // WS
        item_text = "WS";
        item_text += ":" + QString::number(input_val(item_text));
        break;

    case 4:   // SACK Premited
        item_text = "SACK";
        break;
        /*
    case 5:   // SACK
        item_text = "S";
        break;

    case 6:   // Echo
        item_text = "E";
        break;
    */
    case 5:   // Time
        item_text = "T";
        item_text += ":" + QString::number(input_val("time start"));
        item_text += "-" + QString::number(input_val("time end"));
        break;
    }

    ui->list_new->addItem(item_text);
    ui->list_new->setCurrentRow(ui->list_new->count() - 1);
}

void tcp_opt::push_del()
{
    int current_row = ui->list_new->currentRow();
    ui->list_new->removeItemWidget(ui->list_new->takeItem(current_row));
}

void tcp_opt::push_ins()
{
    QString item_text = ui->list_all->currentItem()->text();

    switch(ui->list_all->currentRow()) {
    case 2:     // MSS
        item_text = "MSS";
        item_text += ":" + QString::number(input_val(item_text));
        break;

    case 3:    // WS
        item_text = "WS";
        item_text += ":" + QString::number(input_val(item_text));
        break;

    case 4:   // SACK Premited
        item_text = "SACK";
        break;
        /*
    case 5:   // SACK
        item_text = "S";
        break;

    case 6:   // Echo
        item_text = "E";
        break;
    */
    case 5:   // Time
        item_text = "T";
        item_text += ":" + QString::number(input_val("time start"));
        item_text += "-" + QString::number(input_val("time end"));
        break;
    }

    int current_row = ui->list_new->currentRow();
    ui->list_new->insertItem(current_row + 1, item_text);
    ui->list_new->setCurrentRow(current_row + 1);
}

void tcp_opt::move_up()
{
    int current_row = ui->list_new->currentRow();
    int new_row = current_row - 1;
    if (current_row == 0)
        new_row = ui->list_new->count() - 1;
    QListWidgetItem *item = ui->list_new->takeItem(current_row);
    ui->list_new->insertItem(new_row, item);
    ui->list_new->setCurrentItem(item);
    //        ui->list_new->setCurrentRow(current_row - 1);

}

void tcp_opt::move_down()
{
    int current_row = ui->list_new->currentRow();
    int new_row = current_row ;
    int cnt = ui->list_new->count();
    if (current_row < cnt - 1)
        new_row++;
    else
        new_row = 0;

    QListWidgetItem *item = ui->list_new->takeItem(current_row);
    ui->list_new->insertItem(new_row, item);
    ui->list_new->setCurrentItem(item);
    //        ui->list_new->setCurrentRow(current_row - 1);
}

void tcp_opt::on_pb_clean_clicked()
{
    ui->lb_sa_val->clear();
    ui->lb_s_val->clear();
    ui->list_new->clear();
    ui->sp_ttl->setValue(0);
    ui->sp_win_size->setValue(0);
}

void tcp_opt::on_pb_save_clicked()
{
    //    ui->le_os_name->setText("---121---");
    //    ui->pb_gen_s_sig->click();
    //    ui->pb_gen_sa_sig->click();

    QString sa_sig = ui->lb_sa_val->text();
    QString s_sig = ui->lb_s_val->text();
    QString sig_name = ui->le_os_name->text().remove(QRegularExpression("[-?<>!\"\\\',:]"));
    QString sig_class = ui->le_os_class->text().remove(QRegularExpression("[-?<>!\"\\\',:]"));

    if (sa_sig.isEmpty()) {
        QMessageBox::critical(this, "Error", "SA signature is emptry!");
        return;
    }

    if (s_sig.isEmpty()) {
        QMessageBox::critical(this, "Error", "S signature is emptry!");
        return;
    }

    if (sig_name.isEmpty()) {
        QMessageBox::critical(this, "Error", "Signature name is emptry!");
        return;
    }

    QString fname;
    //    fname = "F://01.02.2020/tcp_small.xml";
    //    fname = "D://Bunin/C++/window/tcp_temp.xml";

    fname = "/home/snow/C++/tcp_small.xml";
//    fname = QFileDialog::getOpenFileName();
//    qDebug() << fname;

    if (fname.isEmpty()){
        QMessageBox::critical(this, QString("Error"), QString("Path to file is emtry!"));
        return ;    }

    QFile file(fname);
    file.open(QIODevice::ReadOnly);

    if (!file.isOpen()) {
        QMessageBox::critical(this, QString("Error"), QString("File not opened!"));
        return;
    }
    //    file.seek(file.pos() - 20);
    //    file.seek(0);
    //    qDebug() << file.pos();
    QDomDocument xml;
    QString err;
    if (!xml.setContent(&file, false, &err)) {
        QMessageBox::critical(this, QString("Error"), QString("Can't read xml!\n") + err);
        return;
    }

    QDomNodeList list = xml.elementsByTagName("fingerprints");
    QDomNode node_start = list.at(0);
    qDebug() << node_start.nodeName();

    QDomElement node_fp = xml.createElement("fingerprint");
    node_fp.setAttribute("os_name", sig_name);
    node_fp.setAttribute("os_class", sig_class);
    node_start.appendChild(node_fp);

    QDomNode node_tcp = xml.createElement("tcp_test");
    node_fp.appendChild(node_tcp);

    QDomElement node_sa = xml.createElement("SA");
    QDomElement node_s = xml.createElement("S");



    QDomAttr attr_sa = xml.createAttribute("tcpsig");
    attr_sa.setValue(sa_sig);
    QDomAttr attr_s = xml.createAttribute("tcpsig");
    attr_s.setValue(s_sig);

    node_sa.setAttribute("tcpsig", sa_sig);
    node_s.setAttribute("tcpsig", s_sig);
    node_tcp.appendChild(node_sa);
    node_tcp.appendChild(node_s);

    file.close();
    file.open(QIODevice::WriteOnly);
    if (!file.isOpen()) {
        QMessageBox::critical(this, QString("Error"), QString("File not opened!"));
        return;
    }

    QTextStream stream(&file);
    stream.flush();
    xml.save(stream, 5);
    file.close();

//    emit ret_signal(value);
    emit refresh_signal();

}

void tcp_opt::on_pb_save_as_clicked()
{
    QString sa_sig = ui->lb_sa_val->text();
    QString s_sig = ui->lb_s_val->text();
    QString sig_name = ui->le_os_name->text().remove(QRegularExpression("[-?<>!\"\\\',:]"));
    QString sig_class = ui->le_os_class->text().remove(QRegularExpression("[-?<>!\"\\\',:]"));

    if (sa_sig.isEmpty()) {
        QMessageBox::critical(this, "Error", "SA signature is emptry!");
        return;
    }

    if (s_sig.isEmpty()) {
        QMessageBox::critical(this, "Error", "S signature is emptry!");
        return;
    }

    if (sig_name.isEmpty()) {
        QMessageBox::critical(this, "Error", "Signature name is emptry!");
        return;
    }

    QString fname;
    //    fname = "F://01.02.2020/tcp_small.xml";
    //    fname = "D://Bunin/C++/window/tcp_temp.xml";
    //        fname = QFileDialog::getOpenFileName();
    fname = QFileDialog::getSaveFileName();
    qDebug() << fname;
    if (fname.isEmpty()){
        QMessageBox::critical(this, QString("Error"), QString("Path to file is emtry!"));
        return ;    }

    QFile file(fname);
    file.open(QIODevice::ReadOnly | QIODevice::WriteOnly);

    if (!file.isOpen()) {
        QMessageBox::critical(this, QString("Error"), QString("File not opened!"));
        return;
    }


    QDomDocument xml;
    QString err;
    if (!xml.setContent(&file, false, &err)) {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "Warning", "It doesn't look like fingerprint base!"
                                                       "\nCannot add fingerprint to the file, write as ONLY ONE fingerprint?",
                                      QMessageBox::Yes|QMessageBox::No);
        if (reply == QMessageBox::Yes) {
            file.close();

            file.open(QIODevice::WriteOnly);
            QTextStream stream(&file);
            stream.flush();
            stream << "<?xml version='1.0' encoding='UTF-8'?>\n";
            stream << "<fingerprints>\n";
            QString fprint = QString("\t\t<fingerprint os_name=\"%1\""
                             " os_class=\"%2\">\n").arg(sig_name, sig_class);
            stream << fprint;
            stream << "\t\t\t\t<tcp_tests>\n";
            stream << QString("\t\t\t\t\t\t<SA tcp_sig=\"%1\"/>\n").arg(sa_sig);
            stream << QString("\t\t\t\t\t\t<S tcp_sig=\"%1\"/>\n").arg(s_sig);
            stream << "\t\t\t\t</tcp_tests>\n";
            stream << "\t\t</fingerprint>\n";
            stream << "</fingerprints>";

            file.close();
            return;
        } else {
            qDebug() << " was *not* clicked";
            return;
        }
    }
    else {

        QDomNodeList list = xml.elementsByTagName("fingerprints");
        QDomNode node_start = list.at(0);
        qDebug() << node_start.nodeName();

        QDomElement node_fp = xml.createElement("fingerprint");
        node_fp.setAttribute("os_name", sig_name);
        node_fp.setAttribute("os_class", sig_class);
        node_start.appendChild(node_fp);

        QDomNode node_tcp = xml.createElement("tcp_test");
        node_fp.appendChild(node_tcp);

        QDomElement node_sa = xml.createElement("SA");
        QDomElement node_s = xml.createElement("S");



        QDomAttr attr_sa = xml.createAttribute("tcpsig");
        attr_sa.setValue(sa_sig);
        QDomAttr attr_s = xml.createAttribute("tcpsig");
        attr_s.setValue(s_sig);

        node_sa.setAttribute("tcpsig", sa_sig);
        node_s.setAttribute("tcpsig", s_sig);
        node_tcp.appendChild(node_sa);
        node_tcp.appendChild(node_s);

        file.close();
        file.open(QIODevice::WriteOnly);
        if (!file.isOpen()) {
            QMessageBox::critical(this, QString("Error"), QString("File not opened!"));
            return;
        }

        QTextStream stream(&file);
        stream.flush();
        xml.save(stream, 5);
        file.close();
    }
}

