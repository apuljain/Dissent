#include "LRSAuthenticator.hpp"
#include "LRVerifier.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSAuthenticator::LRSAuthenticator(
    const QVector<QSharedPointer<PublicIdentity> > &public_ident):
    _public_ident(public_ident)
  {
  }

  QPair<bool, PublicIdentity> LRSAuthenticator::VerifyResponse(
    const Connections::Id &member, const QVariant &data)
  {
    QByteArray _context_tag(10,'a');
    QByteArray _message(10, 'b');

    QVector<QSharedPointer<AsymmetricKey> > _public_ident_asymm;
    //Get Asymmetric keys from public_idents.

    for(QVector<QSharedPointer<PublicIdentity> >::const_iterator itr =
        _public_ident.begin(); itr != _public_ident.end(); ++itr)
    {
      _public_ident_asymm.push_back((*itr)->GetVerificationKey());
    }

    LRVerifier autho(_public_ident_asymm, _context_tag);
    return (autho.LRVerify(_message, member, data));
  }

}
}
}
