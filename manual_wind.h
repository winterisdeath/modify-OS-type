#ifndef MANUAL_WIND_H
#define MANUAL_WIND_H

#include <QWidget>

namespace Ui {
class manual_wind;
}

class manual_wind : public QWidget
{
    Q_OBJECT

public:
    explicit manual_wind(u_char *packet, u_int* size, QWidget *parent = nullptr);
    ~manual_wind();
    bool end_modify = false;
    bool drop = false;
    void get_packet(u_char *packet, u_int &size);
private slots:
    void on_pushButton_clicked();

    void on_pb_drop_clicked();

private:
    Ui::manual_wind *ui;
};

#endif // MANUAL_WIND_H
