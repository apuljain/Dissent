#include "LRSAuthenticate.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSAuthenticate::LRSAuthenticate(const QVector<QSharedPointer<PublicIdentity> > &public_ident,
    const QSharedPointer<PrivateIdentity> &priv_ident,
    const Integer &g, const Integer &p, const Integer &q, const int self_ident):
    _public_ident(public_ident), _priv_ident(priv_ident),
    _g(g), _p(p), _q(q),
    _num_members(public_ident.count()), _self_identity(self_ident)
  {
      _signature = QSharedPointer<LRSignature>(new LRSignature());
  }

  const QByteArray LRSAuthenticate::GetPublicIdentByteArray()
  {
    QByteArray value;

    for(QVector<QSharedPointer<PublicIdentity> >::const_iterator itr = _public_ident.begin();
      itr != _public_ident.end(); ++itr)
    {
      QSharedPointer<Crypto::CppDsaPublicKey> publ_k = (*itr)->GetVerificationKey().dynamicCast<CppDsaPublicKey>();
      value.append(publ_k->GetPublicElement().GetByteArray());
    }

    return value;
  }

  QVariant LRSAuthenticate::PrepareForChallenge()
  {
    QByteArray input_hash_byte = GetPublicIdentByteArray();

    //Calculate hash = H(public_keys) and map it to an element in the group.
    Crypto::CppHash hash_object;
    Integer group_hash = (Integer(hash_object.ComputeHash(input_hash_byte)))%_q;
    group_hash = _g.Pow(group_hash, _p);

    QSharedPointer<Crypto::CppDsaPrivateKey> priv_key = _priv_ident->GetSigningKey().dynamicCast<CppDsaPrivateKey>();

    _signature->SetTag(group_hash.Pow(priv_key->GetPrivateExponent(), _p));

    QByteArray random_byte_array(1500, '0');

    QScopedPointer<Utils::Random> rng(Crypto::CryptoFactory::GetInstance().GetLibrary()->GetRandomNumberGenerator());
    rng->GenerateBlock(random_byte_array);

    //Get random element of the group.
    Integer u(random_byte_array);
    u = u%_q;

    QVector<Integer> ci(_num_members), si(_num_members);

    input_hash_byte = GetPublicIdentByteArray() + _signature->GetTag().GetByteArray() +
      _g.Pow(u, _p).GetByteArray() + group_hash.Pow(u, _p).GetByteArray();

    hash_object.Restart();
    Integer b = Integer(hash_object.ComputeHash(input_hash_byte));

    ci[(_self_identity + 1) % _num_members] = b;

    for(int i = (_self_identity + 1) % _num_members; i != _self_identity; i = (i + 1)%_num_members)
    {
      rng->GenerateBlock(random_byte_array);

      si[i] = (Integer(random_byte_array)%_q);

      QSharedPointer<Crypto::CppDsaPublicKey> publ_k = _public_ident[i]->GetVerificationKey().dynamicCast<CppDsaPublicKey>();

      input_hash_byte = GetPublicIdentByteArray() + _signature->GetTag().GetByteArray() +
        ((_g.Pow(si[i], _p) * publ_k->GetPublicElement().Pow(ci[i], _p)) % _p).GetByteArray()
        + ((group_hash.Pow(si[i], _p) * _signature->GetTag().Pow(ci[i], _p)) % _p).GetByteArray();

      //compute hash
      hash_object.Restart();
      ci[(i+1)%_num_members] = Integer(hash_object.ComputeHash(input_hash_byte));
    }

    si[_self_identity] = ((u % _q) - ((priv_key->GetPrivateExponent())*(ci[_self_identity]) % _q)) % _q;

    //update _signature
    _signature->SetS(si);
    _signature->SetC(ci[0]);

    return QVariant::fromValue(_signature);
  }
}
}
}

