#include <QList>
#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Library.hpp"
#include "LRSAuthenticate.hpp"
#include "LRSigner.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSAuthenticate::LRSAuthenticate(
    const QVector<QSharedPointer<PublicIdentity> > &public_ident,
    const QSharedPointer<PrivateIdentity> &priv_ident):
    _public_ident(public_ident), _priv_ident(priv_ident)
  {
  }

  QVariant LRSAuthenticate::PrepareForChallenge()
  {
    return QVariant();
  }

  QPair<bool, QVariant> LRSAuthenticate::ProcessChallenge(const QVariant & data)
  {
    QByteArray _context_tag(10, 'a');
    QByteArray _message(10, 'b');
    QVector<QSharedPointer<AsymmetricKey> > _public_ident_asymm;
    //Get Asymmetric keys from public_idents.

    for(QVector<QSharedPointer<PublicIdentity> >::const_iterator itr =
        _public_ident.begin(); itr != _public_ident.end(); ++itr)
    {
      _public_ident_asymm.push_back((*itr)->GetVerificationKey());
    }
    LRSigner authe(_public_ident_asymm, _priv_ident->GetSigningKey(), _context_tag);

    //create new public_identity
    Crypto::Library *lib = Crypto::CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Crypto::AsymmetricKey> skey(lib->CreatePrivateKey());
    QSharedPointer<Crypto::DiffieHellman> dh(lib->CreateDiffieHellman());

    _new_priv_ident = PrivateIdentity(_priv_ident->GetLocalId(), skey, dh,  true);		//FIXME

    _new_pub_ident = GetPublicIdentity(_new_priv_ident);

    QByteArray byte_new_ident;
    QDataStream stream(&byte_new_ident, QIODevice::WriteOnly);
    stream << _new_pub_ident;

    QVariantList list;
    list.append(byte_new_ident);
    list.append(authe.LRSign(_message));
    return QPair<bool, QVariant>(true, list);
  }
}
}
}

