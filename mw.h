#ifndef MW_H
#define MW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class mw; }
QT_END_NAMESPACE

class mw : public QMainWindow
{
    Q_OBJECT



private:
    Ui::mw *ui;
    bool _auto = false;
    bool _semi = false;
    bool _manual = false;
    bool _ttl = false;
    bool _ip_src = false;
    bool _ip_dst = false;

public:
    mw(QWidget *parent = nullptr);
    ~mw();

    int get_num_dev_1();
    int get_num_dev_2();

    bool check_auto()   { return _auto; }
    bool check_semi()   { return _semi; }
    bool check_manual() { return _manual; }
    bool check_ttl()    { return  _ttl; }
    bool check_ip_src()     { return _ip_src; }
    bool check_ip_dst()     { return _ip_dst; }

    int get_ttl(int num);
    std::vector<int> get_ip_dst(int type);
    std::vector<int> get_ip_src(int type);

private slots:
    void click_auto();
    void click_semi();
    void click_manual();
    void click_ttl();
    void click_ip_dst();
    void click_ip_src();
    int start_capturing();
    void exit_capture();
};
#endif // MW_H
