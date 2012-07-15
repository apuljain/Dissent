#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  void AuthPass(const Id &authe_id, NullAuthenticate *authe, NullAuthenticator *autho)
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

    PrivateIdentity client = PrivateIdentity(id,QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id.GetByteArray())),
    QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id.GetByteArray())));

    NullAuthenticate auth_client(client);
    NullAuthenticator auth_leader;

    AuthPass(id, &auth_client, &auth_leader);
  }

  TEST(Authenticate, LRS)
  {
    QVector<QSharedPointer<PublicIdentity> > public_idents;
    QVector<QSharedPointer<PrivateIdentity> > priv_idents;

    int num_members = 5;

    QSharedPointer<CppDsaPrivateKey> base_key(new CppDsaPrivateKey());
    Integer generator = base_key->GetGenerator();
    Integer subgroup = base_key->GetSubgroup();
    Integer modulus = base_key->GetModulus();

    for(int i = 0; i < num_members; i++)
    {
      QSharedPointer<CppDsaPrivateKey> private_key(new CppDsaPrivateKey(modulus, subgroup, generator));

      Id id(i);

      QSharedPointer<PrivateIdentity> pr_id = QSharedPointer<PrivateIdentity>
        (new PrivateIdentity(id, QSharedPointer<AsymmetricKey>(private_key), QSharedPointer<DiffieHellman>(), true));

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
        (new PublicIdentity(pr_id->GetLocalId(), skey, dh_pub, pr_id->GetSuperPeer()));

      public_idents.append(pub_id);
    }

    //Testing private_public key pairs.
    for(int j = 0; j < num_members; j++)
    {
      QSharedPointer<CppDsaPublicKey> t1 = public_idents[j]->GetVerificationKey().dynamicCast<CppDsaPublicKey>();
      QSharedPointer<CppDsaPrivateKey> t2 = priv_idents[j]->GetSigningKey().dynamicCast<CppDsaPrivateKey>();
      EXPECT_EQ(generator.Pow(t2->GetPrivateExponent(), modulus), t1->GetPublicElement());
      EXPECT_EQ(priv_idents[j]->GetLocalId(), public_idents[j]->GetId());
    }

    //Instantiate client and server objects.
    LRSAuthenticate auth_client(public_idents, priv_idents[0], generator, modulus, subgroup, 0);
    LRSAuthenticator auth_leader(public_idents, generator, modulus, subgroup);

    QVariant m1 = auth_client.PrepareForChallenge();

    QPair<bool, PublicIdentity> r2 = auth_leader.VerifyResponse(priv_idents[0]->GetLocalId(), m1);

    EXPECT_TRUE(r2.first);
  }
}
}
