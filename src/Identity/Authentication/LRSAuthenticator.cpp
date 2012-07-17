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
    LRVerifier autho(_public_ident, _context_tag, _g, _p, _q);
    return (autho.LRVerify(_message, member, data));
  }

}
}
}
