#include <QString>
#include <QtTest>
#include <QCoreApplication>

class CBitCoinExplorer_Test : public QObject
{
    Q_OBJECT

public:
    CBitCoinExplorer_Test();

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void testCase1_data();
    void testCase1();
};

CBitCoinExplorer_Test::CBitCoinExplorer_Test()
{
}

void CBitCoinExplorer_Test::initTestCase()
{
}

void CBitCoinExplorer_Test::cleanupTestCase()
{
}

void CBitCoinExplorer_Test::testCase1_data()
{
    QTest::addColumn<QString>("data");
    QTest::newRow("0") << QString();
}

void CBitCoinExplorer_Test::testCase1()
{
    QFETCH(QString, data);
    QVERIFY2(true, "Failure");
}

QTEST_MAIN(CBitCoinExplorer_Test)

#include "tst_cbitcoinexplorer_test.moc"
