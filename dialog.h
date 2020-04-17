#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include <QAbstractButton>
#include <QMessageBox>
#include <QSignalTransition>

namespace Ui {
class dialog;
}

class dialog : public QDialog
{
    Q_OBJECT

public:
    explicit dialog(int &value, bool &check, QString title = nullptr, QWidget *parent = nullptr);
    Ui::dialog *ui;
    ~dialog();

private:

private slots:
    void on_pb_ok_clicked();
    void on_pb_canc_clicked();

signals:
    void ret_signal(int value);
};

#endif // DIALOG_H
