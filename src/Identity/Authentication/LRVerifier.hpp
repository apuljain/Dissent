#ifndef DISSENT_IDENTITY_LR_VERIFIER_H_GUARD
#define DISSENT_IDENTITY_LR_VERIFIER_H_GUARD

#include <QHash>
#include <QVariant>
#include <QPair>
#include "Crypto/Integer.hpp"
#include "Crypto/CppHash.hpp"
#include "Crypto/CppDsaPrivateKey.hpp"
#include "Crypto/CppDsaPublicKey.hpp"
#include "Crypto/AsymmetricKey.hpp"
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
  class LRVerifier {

    public:
      typedef Crypto::Integer Integer;
      typedef Connections::Id Id;
      typedef Identity::PublicIdentity PublicIdentity;
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Crypto::CppDsaPublicKey CppDsaPublicKey;
      typedef Crypto::CppDsaPrivateKey CppDsaPrivateKey;
      typedef Crypto::AsymmetricKey AsymmetricKey;

      virtual ~LRVerifier() {}
      LRVerifier() {}

      /**
       * Constructor to initialize signature object.
       * @param: public_identity set.
       * @param: context_tag - specific to a round.
       * @param: group parameters.
       */
      explicit LRVerifier(
        const QVector<QSharedPointer<AsymmetricKey> > &public_ident,
        const QByteArray &context_tag);

      /**
       * Generate signature of the client.
       */
      virtual QPair<bool, PublicIdentity> LRVerify(const QByteArray &message,
        const Id &member, const QVariant &data);

      /**
       * Function to convert _public_ident vector to QByteArray
       */
      virtual const QByteArray GetPublicIdentByteArray();

    private:
      Integer _g, _p, _q;
      quint32 _num_members;
      const QVector<QSharedPointer<AsymmetricKey> > _public_ident;
      QByteArray _public_ident_byte;
      const QByteArray _context_tag;
  };
 }
}
}
#endif
