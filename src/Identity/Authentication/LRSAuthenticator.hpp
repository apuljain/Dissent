#ifndef DISSENT_IDENTITY_LRS_AUTHENTICATOR_H_GUARD
#define DISSENT_IDENTITY_LRS_AUTHENTICATOR_H_GUARD

#include <QHash>
#include "Crypto/Integer.hpp"
#include "Identity/LRSignature.hpp"
#include "Identity/PublicIdentity.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

   /**
    * Implements Authenticator that authenticates client
    * to be a member of the group.
    */

   class LRSAuthenticator {

     public:

       explicit LRSAuthenticator(const QVector<PublicIdentity> &public_ident,
         const Integer &g, const Integer &p, const Integer &q);

       ~LRSAuthenticator() {}

       /**
        * Verify signature of the client.
        */
       bool VerifySignature(const LRSignature &signature);


       /**
        * Function to convert _public_ident vector to QByteArray
        */
       const QByteArray GetPublicIdentByteArray();

     private:
       const QVector<PublicIdentity> _public_ident;
       const Integer _g, _p, _q;

   };

}
}
}

#endif

