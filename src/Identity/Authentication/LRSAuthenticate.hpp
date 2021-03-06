#ifndef DISSENT_IDENTITY_LRS_AUTHENTICATE_H_GUARD
#define DISSENT_IDENTITY_LRS_AUTHENTICATE_H_GUARD

#include <QHash>
#include "Crypto/Integer.hpp"
#include "Crypto/CppHash.hpp"
#include "Crypto/CppDsaPrivateKey.hpp"
#include "Crypto/CppDsaPublicKey.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Connections/Id.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "IAuthenticate.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  class LRSAuthenticate : public IAuthenticate {
    public:
      typedef Crypto::Integer Integer;
      typedef Crypto::CppDsaPrivateKey CppDsaPrivateKey;
      typedef Crypto::CppDsaPublicKey CppDsaPublicKey;
      typedef Crypto::AsymmetricKey AsymmetricKey;

      LRSAuthenticate(const QVector<QSharedPointer<PublicIdentity> > &public_ident,
        const QSharedPointer<PrivateIdentity> &priv_ident);

      virtual ~LRSAuthenticate() {}

      /**
       * Function to be used when two phase authetication is implemented.
       */
      inline virtual bool RequireRequestChallenge() { return false; }

      /**
       * Not required in one phase authentication.
       */
      virtual QVariant PrepareForChallenge();

      /**
       * Generate Signature and random PublicIdentity.
       * @param data : invalid
       */
      virtual QPair<bool, QVariant> ProcessChallenge(const QVariant & data);

      /**
       * Returns the PrivateIdentity, potentially updated
       * due to the authentication process.
       */
      inline virtual PrivateIdentity GetPrivateIdentity() const {return *_priv_ident;}

    private:
      const QVector<QSharedPointer<PublicIdentity> > _public_ident;
      const QSharedPointer<PrivateIdentity> _priv_ident;
      PublicIdentity _new_pub_ident;
      PrivateIdentity _new_priv_ident;
   };
}
}
}

#endif

