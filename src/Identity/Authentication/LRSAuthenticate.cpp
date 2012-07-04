#include "LRSAuthenticate.hpp"
#include "Crypto/Library.hpp"
#include "Crypto/CppHash.hpp"
#include "Connections/Id.hpp"

namespace Dissent {

namespace Identity {
namespace Authentication {

  LRSAuthenticate::LRSAuthenticate(const QVector<PublicIdentity> &public_ident, const PrivateIdentity &priv_ident,
    const Integer &g, const Integer &p, const Integer &q, const int self_ident = 0):
    _public_ident(public_ident), _priv_ident(priv_ident),
    _g(g), _p(p), _q(q), _lib(Crypto::CryptoFactory::GetInstance().GetLibrary()),
    _num_members(public_ident.Count()), _self_identity(self_ident)
  {
  }

  const QByteArray GetPublicIdentByteArray()
  {
      QByteArray value;

      for(QVector<PublicIdentity>::iterator itr = _public_ident.begin();
        itr != _public_ident.end(); ++itr)
      {
        value.append(*itr.GetDhKey());
      }

      return value;
  }

  const LRSignature LRSAuthenticate::GenerateSignature()
  {
    //prepare input byte array - public_identities + g + p + q.
    QByteArray input_hash_byte = GetPublicIdentByteArray() +
                              _g.GetByteArray() + _p.GetByteArray() + _q.GetByteArray();

    QByteArray group_hash = ComputeHash(input_hash_byte);

    _signature.SetTag(Integer(group_hash).Pow(_priv_ident, _p));

    QByteArray random_byte_array(RandomNumberLength, 0);

    _lib->GetRandomNumberGenerator()->GenerateBlock(random_byte_array);
    Integer u(u_byte_array);

    QVector<Integer> ci, si;

    input_hash_byte = GetPublicIdentByteArray() + _signature.GetTag().GetByteArray() +
      _g.Pow(u, _p).GetByteArray() + _Integer(group_hash).Pow(u, _p).GetByteArray();

    Integer b = Integer(ComputeHash(input_hash_byte));

    ci[(_self_identity + 1) % _num_members] = b;

    for(int i = (_self_identity + 1) % _num_members; i != _self_identity; ++i % _num_members)
    {         
       _lib->GetRandomNumberGenerator()->GenerateBlock(random_byte_array);
       si[i] = Integer(random_byte_array);

       //prepare input hash string
       input_hash_byte = GetPublicIdentByteArray() + signature.GetTag().GetByteArray() +
         (_g.Pow(si[i], _p) * Integer(_public_ident[i].GetVerificationKey()->GetByteArray()).Pow(ci[i], _p)) % _p
         + (Integer(group_hash).Pow(si[i], _p) * _signature.GetTag().Pow(ci[i], _p)) % _p;

       //compute hash
       ci[i + 1] = Integer(ComputeHash(input_hash_byte));
    }

    si[_self_identity] = (u % _q - (Integer(_priv_ident.GetSigningKey()->GetByteArray()) * ci[_self_identity]) % _q) % _q;

    //update _signature
    _signature.SetS(si);
    _signature.SetC(ci[0]);

    return _signature;
  }


}
}
}

