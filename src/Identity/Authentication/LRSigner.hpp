#ifndef DISSENT_IDENTITY_LR_SIGNER_H_GUARD
#define DISSENT_IDENTITY_LR_SIGNER_H_GUARD

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
  class LRSigner {

    public:
      typedef Crypto::Integer Integer;
      typedef Connections::Id Id;
      typedef Identity::PublicIdentity PublicIdentity;
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Crypto::CppDsaPublicKey CppDsaPublicKey;
      typedef Crypto::CppDsaPrivateKey CppDsaPrivateKey;
      typedef Crypto::AsymmetricKey AsymmetricKey;

      virtual ~LRSigner() {}
      LRSigner() {}

      /**
       * Constructor to initialize signature object.
       * @param: public_identity set.
       * @param: context_tag - specific to a round.
       * @param: group parameters.
       */
      explicit LRSigner(
        const QVector<QSharedPointer<AsymmetricKey> > &public_ident,
        const QSharedPointer<AsymmetricKey> &priv_ident,
        const QByteArray &context_tag);

      /**
       * Generate signature of the client.
       */
      virtual QVariant LRSign(const QByteArray &message);

      /**
       * Function to convert _public_ident vector to QByteArray
       */
      virtual const QByteArray GetPublicIdentByteArray();

    private:
      Integer _g, _p, _q;
      quint32 _self_identity, _num_members;
      const QVector<QSharedPointer<AsymmetricKey> > _public_ident;
      QByteArray _public_ident_byte;
      const QSharedPointer<AsymmetricKey> _priv_ident;
      const QByteArray _context_tag;

  };
 }
}
}
#endif
