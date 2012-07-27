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
   * Function to test LRS code for Honest Signer and Verifier.
   * @param public identities.
   * @param private identity of the authenticating client.
   */
  void LRSAuthPass(QVector<QSharedPointer<PublicIdentity> > &public_idents,
    QVector<QSharedPointer<PrivateIdentity> > &priv_idents)
  {
    LRSAuthenticate auth_client(public_idents, priv_idents[0]);
    LRSAuthenticator auth_leader(public_idents);

    //create dummy data to comply with ProcessChallenge interface.
    QVariant data;
    QPair<bool, QVariant> m1 = auth_client.ProcessChallenge(data);
    QPair<bool, PublicIdentity> r2 = auth_leader.VerifyResponse(
                                       priv_idents[0]->GetLocalId(), m1.second);
    EXPECT_TRUE(r2.first);
 }

  /**
   * Function to Generate BenchMarking results.
   * @param public identities.
   * @param private identity of the authenticating client.
   */
  void LRSAuthBenchMark(QVector<QSharedPointer<PublicIdentity> > &public_idents,
    QVector<QSharedPointer<PrivateIdentity> > &priv_idents)
  {
    LRSAuthenticate auth_client(public_idents, priv_idents[0]);
    LRSAuthenticator auth_leader(public_idents);

    QFile file("/home/apul/Dissent_Project/Repo/Dissent_david/BenchMark.txt");
    file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Append);
    QTextStream out(&file);
    qint64 time_start = QDateTime::currentMSecsSinceEpoch();

    //create dummy data to comply with ProcessChallenge interface.
    QVariant data;
    QPair<bool, QVariant> m1 = auth_client.ProcessChallenge(data);

    qint64 time_taken1 = QDateTime::currentMSecsSinceEpoch() - time_start;
    time_start = QDateTime::currentMSecsSinceEpoch();
    out << "LRS Generation time for " << public_idents.count() << " members is: " << time_taken1 << " ms.\n";

    QPair<bool, PublicIdentity> r2 = auth_leader.VerifyResponse(
                                       priv_idents[0]->GetLocalId(), m1.second);

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
   */
  void LRSAuthFail(QVector<QSharedPointer<PublicIdentity> > &public_idents,
    QVector<QSharedPointer<PrivateIdentity> > &priv_idents)
  {

    //Failure due to Double authentication attempt.
    LRSAuthenticate auth_client(public_idents, priv_idents[0]);
    LRSAuthenticator auth_leader(public_idents);

    //Create dummy data to comply with ProcessChallenge interface.
    QVariant data;
    QPair<bool, QVariant> m1 = auth_client.ProcessChallenge(data);
    QPair<bool, PublicIdentity> r2 = auth_leader.VerifyResponse(
                                         priv_idents[0]->GetLocalId(), m1.second);

    //First time authentication so expect true.
    EXPECT_TRUE(r2.first);

    r2 = auth_leader.VerifyResponse(priv_idents[0]->GetLocalId(), m1.second);

    //Attempt to authenticate twice so expect false.
    EXPECT_FALSE(r2.first);

    //Failure due to different sets of public keys with client and leader.
    LRSAuthenticate auth_client_test3(public_idents, priv_idents[0]);
    public_idents[0] = public_idents[1];
    LRSAuthenticator auth_leader_test3(public_idents);
       
    m1 = auth_client_test3.ProcessChallenge(data);
    r2 = auth_leader_test3.VerifyResponse(priv_idents[0]->GetLocalId(), m1.second);

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
      //Call for fail tests.
      LRSAuthFail(public_idents, priv_idents);
      //Call for Benchmarking results
      LRSAuthBenchMark(public_idents, priv_idents);

    }


  }
}
}
