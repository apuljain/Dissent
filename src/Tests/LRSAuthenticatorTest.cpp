#include "DissentTest.hpp"
#include <QDebug>

namespace Dissent {
namespace Tests {

  TEST(LRSAuthenticator, Null)
  {
    QVector<PublicIdentity> pub_ident;
    PublicIdentity pub = PublicIdentity();
    pub_ident.push_back(pub);

    Integer g(3), p(7), q(6);

    QString as = "0xA";
    Integer te(as);
    QDataStream str;

    qDebug() << te.ToString() << "FASDFADSF\n";
    LRSAuthenticator auth_leader(pub_ident, g, p, q);
    PrivateIdentity priv = PrivateIdentity();
    LRSAuthenticate auth_client(pub_ident, priv, g, p, q);

//    EXPECT_TRUE(auth_leader.VerifySignature(c,s,y));

   }
}
}
