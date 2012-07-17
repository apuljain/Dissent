#ifndef DISSENT_IDENTITY_LRS_AUTHENTICATE_H_GUARD
#define DISSENT_IDENTITY_LRS_AUTHENTICATE_H_GUARD

#include <QHash>
#include "Crypto/Integer.hpp"
#include "Crypto/CppHash.hpp"
#include "Crypto/CppDsaPrivateKey.hpp"
#include "Crypto/CppDsaPublicKey.hpp"
#include "Connections/Id.hpp"
#include "Identity/Authentication/LRSignature.hpp"
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

      LRSAuthenticate(const QVector<QSharedPointer<PublicIdentity> > &public_ident,
        const QSharedPointer<PrivateIdentity> &priv_ident,
        const Integer &g, const Integer &p, const Integer &q);

      virtual ~LRSAuthenticate() {}

      /**
       * Function to be used when two phase authetication is implemented.
       */
      inline virtual bool RequireRequestChallenge() { return false; }

      /**
       * Generate signature of the client.
       */
      virtual QVariant PrepareForChallenge();

      /**
       * Processes a challenge from the server and produce the response. To be implemented.
       * @param data the challenge
       */
      virtual QPair<bool, QVariant> ProcessChallenge(const QVariant & data) {}

      /**
       * Returns the PrivateIdentity, potentially updated
       * due to the authentication process
       */
      inline virtual PrivateIdentity GetPrivateIdentity() const {return *_priv_ident;}

    private:
      const QVector<QSharedPointer<PublicIdentity> > _public_ident;
      const QSharedPointer<PrivateIdentity> _priv_ident;
      const Integer _g, _p, _q;
   };
}
}
}

#endif

