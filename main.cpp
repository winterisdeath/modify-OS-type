#include "mw.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    mw w;
    w.show();
    return a.exec();
}
