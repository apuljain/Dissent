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
      LRSigner authe(_public_ident, _priv_ident, _context_tag, _g, _p, _q);
      return (authe.LRSign(_message));
  }
}
}
}

