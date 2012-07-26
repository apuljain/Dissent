#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  /**
   * Function to test Null Authenticator test case.
   * @param authenticating cient id.
   * @param authenticating client object.
   * @param authenticator object.
   */
  void AuthPass(const Id &authe_id, NullAuthenticate *authe,
                 NullAuthenticator *autho)
  {
    QVariant m1 = authe->PrepareForChallenge();
    QVariant m2 = autho->RequestChallenge(authe_id, m1);
    QPair<bool,QVariant> r1 = authe->ProcessChallenge(m2);

    EXPECT_TRUE(r1.first);

    QPair<bool,PublicIdentity> r2 = autho->VerifyResponse(authe_id, r1.second);
    EXPECT_TRUE(r2.first);
    EXPECT_EQ(r2.second, GetPublicIdentity(authe->GetPrivateIdentity()));
  }

  TEST(Authenticate, Null)
  {

    Crypto::Library *lib = Crypto::CryptoFactory::GetInstance().GetLibrary();

    Id id;

    PrivateIdentity client =
     PrivateIdentity(id,
      QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id.GetByteArray())),
      QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id.GetByteArray())));

    NullAuthenticate auth_client(client);
    NullAuthenticator auth_leader;

    AuthPass(id, &auth_client, &auth_leader);
  }

  /**
   * Function to test LRS code for "Pass" test case.
   * @param public identities.
   * @param private identity of the authenticating client.
   * @param group parameters - generator, modulus and subgroup size.
   */
  void LRSAuthPass(QVector<QSharedPointer<PublicIdentity> > &public_idents,
    QVector<QSharedPointer<PrivateIdentity> > &priv_idents)
  {
    //Instantiate client and server objects.

    QSharedPointer<Crypto::CppDsaPrivateKey> priv_key =
      priv_idents[0]->GetSigningKey().dynamicCast<CppDsaPrivateKey>();

    priv_key->GetModulus();

    LRSAuthenticate auth_client(public_idents, priv_idents[0]);
    LRSAuthenticator auth_leader(public_idents);

    QFile file("/home/apul/intern/repo/Dissent_david/BenchMark.txt");
    file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Append);
    QTextStream out(&file);

    qint64 time_start = QDateTime::currentMSecsSinceEpoch();

    QVariant m1 = auth_client.PrepareForChallenge();
    qint64 time_taken1 = QDateTime::currentMSecsSinceEpoch() - time_start;

    time_start = QDateTime::currentMSecsSinceEpoch();

    out << "LRS Generation time for " << public_idents.count() << " members is: " << time_taken1 << " ms.\n";

    QPair<bool, PublicIdentity> r2 = auth_leader.VerifyResponse(
                                       priv_idents[0]->GetLocalId(), m1);

    qint64 time_taken2 = QDateTime::currentMSecsSinceEpoch() - time_start;
    out << "LRS Verification time for " << public_idents.count() << " members is: " << time_taken2 << " ms.\n";
    out << "LRS Total time for: " << public_idents.count() << " members is: " << (time_taken1 + time_taken2) << " ms.\n";
    file.close();

    EXPECT_TRUE(r2.first);
 }

  /**
   * Function to test LRS code for fail test cases.
   * @param public identities.
   * @param private identity of the authenticating client.
   * @param group parameters - generator, modulus and subgroup size.
   */
  void LRSAuthFail(QVector<QSharedPointer<PublicIdentity> > &public_idents,
    QVector<QSharedPointer<PrivateIdentity> > &priv_idents)
  {
    //Fail due to invalid public_private key pair for authenticating client.
    //Instantiate client and server objects.

//    QSharedPointer<CppDsaPrivateKey> t2 =
//      priv_idents[0]->GetSigningKey().dynamicCast<CppDsaPrivateKey>();

//    QSharedPointer<CppDsaPrivateKey> private_key(new CppDsaPrivateKey(t2->GetModulus(), t2->GetSubgroup(), t2->GetGenerator()));
//    Id id(1);
//    QSharedPointer<PrivateIdentity> pr_id = QSharedPointer<PrivateIdentity>
//     (new PrivateIdentity(id, QSharedPointer<AsymmetricKey>(private_key),
//                           QSharedPointer<DiffieHellman>(), true));

//    LRSAuthenticate auth_client_test1(public_idents, pr_id);

//    LRSAuthenticator auth_leader_test1(public_idents);

//    QVariant m1 = auth_client_test1.PrepareForChallenge();
//    QPair<bool, PublicIdentity> r2 = auth_leader_test1.VerifyResponse(
//                                      pr_id->GetLocalId(), m1);

//    EXPECT_FALSE(r2.first);

    //Fail due to different sets of public keys with client and leader.
    LRSAuthenticate auth_client_test3(public_idents, priv_idents[0]);
    public_idents[0] = public_idents[1];
    LRSAuthenticator auth_leader_test3(public_idents);
    QVariant m1 = auth_client_test3.PrepareForChallenge();
    QPair<bool, PublicIdentity> r2 = auth_leader_test3.VerifyResponse(priv_idents[0]->GetLocalId(), m1);

    EXPECT_FALSE(r2.first);
  }

  TEST(Authenticate, LRS)
  {
    QVector<QSharedPointer<PublicIdentity> > public_idents;
    QVector<QSharedPointer<PrivateIdentity> > priv_idents;

    QDir pubdir("public");
    QDir privdir("private");

    pubdir.setFilter(QDir::NoDotAndDotDot | QDir::Files | QDir::NoSymLinks);
    privdir.setFilter(QDir::NoDotAndDotDot | QDir::Files | QDir::NoSymLinks);

    QStringList list_pub = pubdir.entryList();
    QStringList list_priv = privdir.entryList();

    int num_members = list_pub.count();

    for(int j = 2; j < num_members + 1; j = j*2)
    {
        public_idents.clear();
        priv_idents.clear();
        for(int i = 0; i < j; i++)
        {
            QSharedPointer<CppDsaPrivateKey> private_key(
              new CppDsaPrivateKey("private/" + list_priv.at(i)));

            Id id(i);
            QSharedPointer<PrivateIdentity> pr_id = QSharedPointer<PrivateIdentity>
              (new PrivateIdentity(id, QSharedPointer<AsymmetricKey>(private_key),
                                 QSharedPointer<DiffieHellman>(), true));

            priv_idents.append(pr_id);

            AsymmetricKey *key = 0;
            QByteArray dh_pub = QByteArray();

            if(pr_id->GetSigningKey())
            {
              key = pr_id->GetSigningKey()->GetPublicKey();
            }

            if(pr_id->GetDhKey())
            {
              dh_pub = pr_id->GetDhKey()->GetPublicComponent();
            }

            QSharedPointer<AsymmetricKey> skey(key);

            QSharedPointer<PublicIdentity> pub_id = QSharedPointer<PublicIdentity>
              (new PublicIdentity(pr_id->GetLocalId(), skey, dh_pub,
                                 pr_id->GetSuperPeer()));

            public_idents.append(pub_id);
         }

        //Call for success test.
        LRSAuthPass(public_idents, priv_idents);
    }

//    //Testing private_public key pairs.
//    for(int j = 0; j < num_members; j++)
//    {
//      QSharedPointer<CppDsaPublicKey> t1 =
//        public_idents[j]->GetVerificationKey().dynamicCast<CppDsaPublicKey>();
//      QSharedPointer<CppDsaPrivateKey> t2 =
//        priv_idents[j]->GetSigningKey().dynamicCast<CppDsaPrivateKey>();

//      EXPECT_EQ(t1->GetGenerator(), t2->GetGenerator());
//      EXPECT_EQ(t1->GetModulus(), t2->GetModulus());
//      EXPECT_EQ(t1->GetSubgroup(), t2->GetSubgroup());

//      EXPECT_EQ(t2->GetGenerator().Pow(t2->GetPrivateExponent(), t2->GetModulus()),
//                              t1->GetPublicElement());
//    }


    //Call for fail tests.
    LRSAuthFail(public_idents, priv_idents);

  }
}
}
