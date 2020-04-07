#ifndef TCP_OPT_H
#define TCP_OPT_H

#include <QMainWindow>
#include <QDomDocument>
#include <QFile>
#include <QMessageBox>
#include <QDialog>
#include <QDebug>
#include <dialog.h>
#include <QRegularExpression>
#include <QFileDialog>

QT_BEGIN_NAMESPACE
namespace Ui { class tcp_opt; }
QT_END_NAMESPACE

struct os_sig
{
    QString os_name;
    QString os_class;
    QString s_params;
    QString sa_params;
};

class tcp_opt : public QWidget
{
    Q_OBJECT

public:
    tcp_opt(QWidget *parent = nullptr);
    ~tcp_opt();
    int _value = 0;
    bool _check = false;

private:
    Ui::tcp_opt *ui;
    int _ret_val = -1;
    QString gen_sig();
    QString s_sig;
    QString sa_sig;

private slots:
    void push_add();
    void push_del();
    void move_up();
    void move_down();
    void push_ins();
    void write_sa_sig();
    void write_s_sig();

    int input_val(QString title);

    void new_func(int);


    void on_pb_clean_clicked();
    void on_pb_save_clicked();
    void on_pb_save_as_clicked();

signals:
    void refresh_signal();
};
#endif // tcp_opt_H
