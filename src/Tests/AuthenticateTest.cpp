#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Authenticate, Null) {

    Crypto::Library *lib = Crypto::CryptoFactory::GetInstance().GetLibrary();
    QByteArray id(20, 0);
    lib->GetRandomNumberGenerator()->GenerateBlock(id);

    PrivateIdentity client = PrivateIdentity(Id(id),QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id)),
      QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id)));

    NullAuthenticate auth_client(client);
    NullAuthenticator auth_leader;

    QVariant m1 = auth_client.PrepareForChallenge();
    QVariant m2 = auth_leader.RequestChallenge(client.GetLocalId(), m1);
    QPair<bool,QVariant> r1 = auth_client.ProcessChallenge(m2);

    EXPECT_TRUE(r1.first);

    QPair<bool,PublicIdentity> r2 = auth_leader.VerifyResponse(client.GetLocalId(), r1.second);
    EXPECT_TRUE(r2.first);
    EXPECT_EQ(r2.second, GetPublicIdentity(client));
  }

}
}
