#ifndef DISSENT_IDENTITY_LR_VERIFIER_H_GUARD
#define DISSENT_IDENTITY_LR_VERIFIER_H_GUARD

#include <QHash>
#include <QVariant>
#include <QPair>
#include "Crypto/Integer.hpp"
#include "Crypto/CppHash.hpp"
#include "Crypto/CppDsaPrivateKey.hpp"
#include "Crypto/CppDsaPublicKey.hpp"
#include "Connections/Id.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "IAuthenticator.hpp"

namespace Dissent {
namespace Identity {
    namespace Authentication {
  /**
   * Signer class. It generates LR signature.
   */
  class LRVerify {

    public:
      typedef Crypto::Integer Integer;
      typedef Connections::Id Id;
      typedef Identity::PublicIdentity PublicIdentity;
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Crypto::CppDsaPublicKey CppDsaPublicKey;
      typedef Crypto::CppDsaPrivateKey CppDsaPrivateKey;

      virtual ~LRVerify() {}

      LRVerify() {}

      /**
       * Constructor to initialize signature object.
       * @param: public_identity set.
       * @param: context_tag - specific to a round.
       * @param: group parameters.
       */
      explicit LRVerifier(
        const QVector<QSharedPointer<PublicIdentity> > &public_ident,
        const QByteArray &context_tag,
        const Integer &g, const Integer &p, const Integer &q);

      /**
       * Generate signature of the client.
       */
      virtual QVariant LRVerify(const QByteArray &message);

      /**
       * Function to convert _public_ident vector to QByteArray
       */
      virtual const QByteArray GetPublicIdentByteArray();

    private:
      const Integer _g, _p, _q;
      const QVector<QSharedPointer<PublicIdentity> > &_public_ident;
      const QByteArray &_context_tag;

  };
 }
}
}
#endif
