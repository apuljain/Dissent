#include "LRSAuthenticate.hpp"
#include "LRSigner.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSAuthenticate::LRSAuthenticate(
    const QVector<QSharedPointer<PublicIdentity> > &public_ident,
    const QSharedPointer<PrivateIdentity> &priv_ident,
    const Integer &g, const Integer &p, const Integer &q):
    _public_ident(public_ident), _priv_ident(priv_ident),
    _g(g), _p(p), _q(q)
  {
  }

  QVariant LRSAuthenticate::PrepareForChallenge()
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

    return (authe.LRSign(_message));
  }
}
}
}

