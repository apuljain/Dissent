#ifndef DISSENT_IDENTITY_LRS_AUTHENTICATOR_H_GUARD
#define DISSENT_IDENTITY_LRS_AUTHENTICATOR_H_GUARD

#include <QHash>
#include <QVariant>
#include <QPair>
#include "Crypto/Integer.hpp"
#include "Crypto/CppHash.hpp"
#include "Crypto/CppDsaPrivateKey.hpp"
#include "Crypto/CppDsaPublicKey.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Connections/Id.hpp"
#include "Identity/Authentication/LRSignature.hpp"
#include "Identity/PublicIdentity.hpp"
#include "IAuthenticator.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  class LRSAuthenticator : public IAuthenticator {
    public:
      typedef Crypto::Integer Integer;
      typedef Connections::Id Id;
      typedef Crypto::CppDsaPublicKey CppDsaPublicKey;
      typedef Crypto::CppDsaPrivateKey CppDsaPrivateKey;
      typedef Crypto::AsymmetricKey AsymmetricKey;

      virtual ~LRSAuthenticator() {}

      LRSAuthenticator(const QVector<QSharedPointer<PublicIdentity> > &public_ident);

      /**
       * This function to be implemented. This will handle challenge to be sent
       * to authenticating client.
       */
      virtual QVariant RequestChallenge(const Id &member, const QVariant &data) {}

      /**
       * Verify signature of the client.
       */
      virtual QPair<bool, PublicIdentity> VerifyResponse(const Id &member,
        const QVariant &data);

     private:
       const QVector<QSharedPointer<PublicIdentity> > _public_ident;
   };
}
}
}

#endif

