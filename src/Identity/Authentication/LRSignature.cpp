#include "LRSignature.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSignature::LRSignature(const Integer &g, const Integer &p, const Integer &q):
    _g(g), _p(p), _q(q)
  {
  }

  const QByteArray LRSignature::GetPublicIdentByteArray(
    const QVector<QSharedPointer<PublicIdentity> > &_public_ident)
  {
    QByteArray value;

    for(QVector<QSharedPointer<PublicIdentity> >::const_iterator itr =
         _public_ident.begin(); itr != _public_ident.end(); ++itr)
    {
      QSharedPointer<Crypto::CppDsaPublicKey> publ_k =
        (*itr)->GetVerificationKey().dynamicCast<CppDsaPublicKey>();
      value.append(publ_k->GetPublicElement().GetByteArray());
    }

    return value;
  }

  QVariant LRSignature::LRSSign(
    const QVector<QSharedPointer<PublicIdentity> > &_public_ident,
    const QSharedPointer<PrivateIdentity> &_priv_ident, const QByteArray &message)
  {
      int _num_members = _public_ident.count();
      int _self_identity = _priv_ident->GetLocalId().GetInteger().GetInt32();

      QByteArray input_hash_byte = GetPublicIdentByteArray(_public_ident);

      //Calculate hash = H(public_keys) and map it to an element in the group.
      Crypto::CppHash hash_object;
      Integer group_hash = (Integer(hash_object.ComputeHash(input_hash_byte)))%_q;
      group_hash = _g.Pow(group_hash, _p);

      QSharedPointer<Crypto::CppDsaPrivateKey> priv_key =
        _priv_ident->GetSigningKey().dynamicCast<CppDsaPrivateKey>();

      QByteArray linkage_tag =
        group_hash.Pow(priv_key->GetPrivateExponent(), _p).GetByteArray();

      QByteArray random_byte_array(1500, '0');

      QScopedPointer<Utils::Random>
       rng(Crypto::CryptoFactory::GetInstance().GetLibrary()->GetRandomNumberGenerator());

      rng->GenerateBlock(random_byte_array);

      //Get random element of the group.
      Integer u(random_byte_array);
      u = u%_q;

      QVector<Integer> ci(_num_members), si(_num_members);

      input_hash_byte = GetPublicIdentByteArray(_public_ident) +
        linkage_tag + message + _g.Pow(u, _p).GetByteArray() +
        group_hash.Pow(u, _p).GetByteArray();

      hash_object.Restart();
      Integer b = Integer(hash_object.ComputeHash(input_hash_byte));

      ci[(_self_identity + 1) % _num_members] = b;

      for(int i = (_self_identity + 1) % _num_members; i != _self_identity;
           i = (i + 1)%_num_members)
      {
        rng->GenerateBlock(random_byte_array);

        si[i] = (Integer(random_byte_array)%_q);

        QSharedPointer<Crypto::CppDsaPublicKey> publ_k =
          _public_ident[i]->GetVerificationKey().dynamicCast<CppDsaPublicKey>();

        input_hash_byte = GetPublicIdentByteArray(_public_ident) + linkage_tag + message +
          ((_g.Pow(si[i], _p) * publ_k->GetPublicElement().Pow(ci[i], _p)) % _p).GetByteArray()
          + ((group_hash.Pow(si[i], _p) * Integer(linkage_tag).Pow(ci[i], _p)) % _p).GetByteArray();

        //compute hash
        hash_object.Restart();
        ci[(i+1)%_num_members] = Integer(hash_object.ComputeHash(input_hash_byte));
      }

      si[_self_identity] = ((u % _q) -
        ((priv_key->GetPrivateExponent())*(ci[_self_identity]) % _q)) % _q;

      QList<QVariant> list, temp;
      list.append(QVariant(ci[0].GetByteArray()));
      for(int i = 0; i < si.count(); i++)
      {
        temp.append(QVariant(si[i].GetByteArray()));
      }
      list.append(QVariant(temp));
      list.append(QVariant(linkage_tag));

      //FIXME: TODO
      //append random public_identity
      //list.append();
      return list;
  }

  QPair<bool, PublicIdentity> LRSignature::LRSVerify(
    const QVector<QSharedPointer<PublicIdentity> > _public_ident,
    const Id &member, const QVariant &data)
  {
    int _num_members = _public_ident.count();
    QList<QVariant> in;
    const QPair<bool, PublicIdentity> invalid(false, PublicIdentity());

    if(!data.canConvert(QVariant::List))
    {
      qWarning() << "Invalid challenge from client: cannot convert to list";
      return invalid;
    }

    in = data.toList();

    if(in.count() != 3 ||
        !in[0].canConvert(QVariant::ByteArray) ||
        !in[1].canConvert(QVariant::List) ||
        !in[2].canConvert(QVariant::ByteArray))
    {
        qWarning() << "Invalid challenge from client: list.count() != 3";
        return invalid;
    }

    _num_members = _public_ident.count();

    //prepare input byte array - public_identities.
    QByteArray input_hash_byte = GetPublicIdentByteArray(_public_ident);

    //Calculate hash = H(public_keys) and map it to an element in the group.
    Dissent::Crypto::CppHash hash_object;
    Integer group_hash = (Integer(hash_object.ComputeHash(input_hash_byte))%_q);
    group_hash = _g.Pow(group_hash, _p);

    Integer zi, zi_dash;
    Integer ci = Integer(in[0].toByteArray());
    QList<QVariant> si_variant = in[1].toList();
    QVector<Integer> si;
    Integer linkage_tag = Integer(in[2].toByteArray());

    for(int i = 0; i < _num_members; i++)
    {
      si.push_back(Integer(si_variant.at(i).toByteArray()));
    }

    for(int i = 0; i < _num_members; i++)
    {
      QSharedPointer<Crypto::CppDsaPublicKey> publ_k =
      _public_ident[i]->GetVerificationKey().dynamicCast<CppDsaPublicKey>();

      zi = (_g.Pow(si[i], _p) * (publ_k->GetPublicElement().Pow(ci, _p))) % _p;

      zi_dash = ((group_hash.Pow(si[i], _p))*(linkage_tag.Pow(ci, _p))) % _p;

      //prepare input hash string
      input_hash_byte = GetPublicIdentByteArray(_public_ident) +
        linkage_tag.GetByteArray() + zi.GetByteArray() +
        zi_dash.GetByteArray();

      //compute hash
      hash_object.Restart();
      ci = Integer(hash_object.ComputeHash(input_hash_byte));

    }

    return QPair<bool, PublicIdentity> (Integer(in[0].toByteArray()) == ci, PublicIdentity());
  }

}
}
}
