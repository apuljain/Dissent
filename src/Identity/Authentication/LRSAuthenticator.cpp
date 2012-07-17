#include "LRSAuthenticator.hpp"
#include "LRSignature.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSAuthenticator::LRSAuthenticator(const QVector<QSharedPointer<PublicIdentity> > &public_ident,
    Integer &g, Integer &p, Integer &q):
    _public_ident(public_ident),
    _g(g), _p(p), _q(q)
  {
    _num_members = public_ident.count();
  }

  QPair<bool, PublicIdentity> LRSAuthenticator::VerifyResponse(
    const Connections::Id &member, const QVariant &data)
  {
    LRSignature autho(_g, _p, _q);
    return (autho.LRSVerify(_public_ident, member, data));
  }

}
}
}
