#include "LRSAuthenticate.hpp"
#include "LRSignature.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSAuthenticate::LRSAuthenticate(
    const QVector<QSharedPointer<PublicIdentity> > &public_ident,
    const QSharedPointer<PrivateIdentity> &priv_ident,
    const Integer &g, const Integer &p, const Integer &q, const int self_ident):
    _public_ident(public_ident), _priv_ident(priv_ident),
    _g(g), _p(p), _q(q),
    _num_members(public_ident.count()), _self_identity(self_ident)
  {
      _signature = QSharedPointer<LRSignature>(new LRSignature());
  }

  QVariant LRSAuthenticate::PrepareForChallenge()
  {
      LRSignature authe(_g, _p, _q);
      return (authe.LRSSign(_public_ident, _priv_ident, ""));
  }
}
}
}

