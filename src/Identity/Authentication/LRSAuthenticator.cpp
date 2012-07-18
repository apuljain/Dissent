#include "LRSAuthenticator.hpp"
#include "LRVerifier.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSAuthenticator::LRSAuthenticator(
    const QVector<QSharedPointer<PublicIdentity> > &public_ident,
    Integer &g, Integer &p, Integer &q):
    _public_ident(public_ident),
    _g(g), _p(p), _q(q)
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
      qDebug() << "Reached Here!";

    }

    LRVerifier autho(_public_ident_asymm, _context_tag);
    qDebug() << "REACHED";
    return (autho.LRVerify(_message, member, data));
  }

}
}
}
