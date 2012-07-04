#ifndef DISSENT_IDENTITY_LRS_AUTHENTICATE_H_GUARD
#define DISSENT_IDENTITY_LRS_AUTHENTICATE_H_GUARD

#include <QHash>
#include "Crypto/Integer.hpp"
#include "Identity/LRSignature.hpp"
#include "Identity/PublicIdentity.hpp"

namespace Dissent {

namespace Crypto {
  class Library;
}

namespace Identity {
namespace Authentication {

   /**
    * Implements Authenticate Class
    * to Generate Signature.
    */

   class LRSAuthenticate {

     public:

       explicit LRSAuthenticate(const QVector<PublicIdentity> &public_ident, const PrivateIdentity &priv_ident,
         const Integer &g, const Integer &p, const Integer &q);

       ~LRSAuthenticate() {}

       /**
        * Generate signature of the client.
        */
       const LRSignature GenerateSignature();

       /**
        * Function to convert _public_ident vector to QByteArray
        */
       const QByteArray GetPublicIdentByteArray();

       static const int RandomNumberLength = 32;

     private:

       const QVector<PublicIdentity> _public_ident;
       const int _num_members, _self_identity;
       const Integer _g, _p, _q;
       const PrivateIdentity _priv_ident;
       LRSignature _signature;

       Crypto::Library *_lib;
   };

}
}
}

#endif

