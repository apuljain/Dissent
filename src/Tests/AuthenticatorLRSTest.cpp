#include "DissentTest.hpp"
#include "Identity/Authentication/NullAuthenticatorLRS.hpp"
namespace Dissent {
namespace Tests {

  TEST(AuthenticatorLRS, Null)
  {
    //create an empty group.
    QSharedPointer<const Group> g = QSharedPointer<const Group> (new Group);

    NullAuthenticatorLRS auth_leader;
    Integer c,y;
    QVector<Integer> s;
    EXPECT_TRUE(auth_leader.VerifySignature(c,s,y));

   }
}
}
