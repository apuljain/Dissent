#ifndef DISSENT_IDENTITY_LRS_SIGNATURE_H_GUARD
#define DISSENT_IDENTITY_LRS_SIGNATURE_H_GUARD

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
   * Signature class. It holds LR Signature components.
   */
  class LRSignature {

    public:
      typedef Crypto::Integer Integer;
      typedef Connections::Id Id;
      typedef Identity::PublicIdentity PublicIdentity;
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Crypto::CppDsaPublicKey CppDsaPublicKey;
      typedef Crypto::CppDsaPrivateKey CppDsaPrivateKey;

      virtual ~LRSignature() {}

      LRSignature() {}

      /**
       * Constructor to initialize signature object.
       * @param: public_identity set.
       * @param: group parameters.
       */
      explicit LRSignature(const Integer &g, const Integer &p, const Integer &q);

      /**
       * Verify signature of the client.
       */
      virtual QPair<bool, PublicIdentity> LRSVerify(
        const QVector<QSharedPointer<PublicIdentity> > _public_ident,
        const Id &member,
        const QVariant &data);

      /**
       * Generate signature of the client.
       */
      virtual QVariant LRSSign(const QVector<QSharedPointer<PublicIdentity> > &_public_ident,
        const QSharedPointer<PrivateIdentity> &_priv_ident,
        const QByteArray &message);

      /**
       * Function to convert _public_ident vector to QByteArray
       */
      virtual const QByteArray GetPublicIdentByteArray(
        const QVector<QSharedPointer<PublicIdentity> > &_public_ident);

    private:
      const Integer _g, _p, _q;
  };
 }
}
}
#endif
