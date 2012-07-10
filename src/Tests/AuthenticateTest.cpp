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

  TEST(Authenticate, Null) {

    Crypto::Library *lib = Crypto::CryptoFactory::GetInstance().GetLibrary();

    Id id;

    PrivateIdentity client = PrivateIdentity(id,QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id.GetByteArray())),
    QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id.GetByteArray())));

    NullAuthenticate auth_client(client);
    NullAuthenticator auth_leader;

    AuthPass(id, &auth_client, &auth_leader);
  }
}
}
