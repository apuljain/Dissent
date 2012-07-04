#include "LRSAuthenticator.hpp"
#include "Crypto/CppHash.hpp"

namespace Dissent {

namespace Identity {
namespace Authentication {

  LRSAuthenticator::LRSAuthenticator(const QVector<PublicIdentity> &public_ident,
    const Integer &g, const Integer &p, const Integer &q):
    _public_ident(public_ident),
    _g(g), _p(p), _q(q)
  {
  }

  const QByteArray GetPublicIdentByteArray()
  {
      QByteArray value;

      for(QVector<PublicIdentity>::iterator itr = _public_ident.begin();
        itr != _public_ident.end(); ++itr)
      {
        value.append(*itr.GetVerificationKey()->GetByteArray());
      }

      return value;
  }

  bool LRSAuthenticator::VerifySignature(const LRSignature &signature)
  {
    //prepare input byte array - public_identities + g + p + q.
    QByteArray input_hash_byte = GetPublicIdentByteArray() +
                              _g.GetByteArray() + _p.GetByteArray() + _q.GetByteArray();

    QByteArray group_hash = ComputeHash(input_hash_byte);

    Integer zi, zi_dash;
    Integer ci = signature.GetC();

    for(int i = 0; i < _public_ident.Count(); i++)
    {
       zi = (_g.Pow(signature.GetSi(i), _p) * Integer(_public_ident[i].GetVerificationKey()->GetByteArray()).Pow(ci, _p)) % _p;

       zi_dash = (Integer(group_hash).Pow(signature.GetSi(i), _p) * signature.GetTag().Pow(ci, _p)) % _p;

       //prepare input hash string
       input_hash_byte = GetPublicIdentByteArray() + signature.GetTag().GetByteArray() +
                         zi.GetByteArray() + zi_dash.GetByteArray();
       //compute hash
       ci = Integer(ComputeHash(input_hash_byte));
    }

    qDebug() << "C:  " << signature.GetC().ToString() << "\n";
    qDebug() << "H': " << ci.ToString() << "\n";

    return (signature.GetC() == ci)
  }


}
}
}
