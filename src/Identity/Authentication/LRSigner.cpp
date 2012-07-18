#include "LRSigner.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSigner::LRSigner(
    const QVector<QSharedPointer<AsymmetricKey> > &public_ident,
    const QSharedPointer<AsymmetricKey> &priv_ident,
    const QByteArray &context_tag):
    _public_ident(public_ident), _priv_ident(priv_ident),
    _context_tag(context_tag)
  {
    //Get Group parameters from private key.

    QSharedPointer<Crypto::CppDsaPrivateKey> priv_key =
      _priv_ident.dynamicCast<CppDsaPrivateKey>();

    _g = priv_key->GetGenerator();
    _p = priv_key->GetModulus();
    _q = priv_key->GetSubgroup();

    //get the self_identity -- by comparing the "matching" public_key in the list.
    qint32 counter = 0;
    _self_identity = -1;

    QSharedPointer<CppDsaPrivateKey> t2 = _priv_ident.dynamicCast<CppDsaPrivateKey>();

    for(QVector<QSharedPointer<AsymmetricKey> >::const_iterator itr =
        _public_ident.begin(); itr != _public_ident.end(); ++itr, ++counter)
    {
      QSharedPointer<CppDsaPublicKey> t1 = (*itr).dynamicCast<CppDsaPublicKey>();
      if(_g.Pow(t2->GetPrivateExponent(), _p) == t1->GetPublicElement())
      {
        _self_identity = counter;
        break;
      }
    }

   if(_self_identity == -1)
      qDebug() << "INVALID PRIVATE KEY. NO CORRESPONDING PUBLIC KEY IN THE ROSTER.";

  }

  const QByteArray LRSigner::GetPublicIdentByteArray()
  {
    QByteArray value;

    for(QVector<QSharedPointer<AsymmetricKey> >::const_iterator itr =
         _public_ident.begin(); itr != _public_ident.end(); ++itr)
    {
      QSharedPointer<Crypto::CppDsaPublicKey> publ_k =
        (*itr).dynamicCast<CppDsaPublicKey>();
      value.append(publ_k->GetPublicElement().GetByteArray());
    }

    return value;
  }

  QVariant LRSigner::LRSign(const QByteArray &message)
  {
    qint32 _num_members = _public_ident.count();

    QByteArray input_hash_byte = GetPublicIdentByteArray() + _context_tag;

    //Calculate hash = H(public_keys) and map it to an element in the group.
    Crypto::CppHash hash_object;
    Integer group_hash = (Integer(hash_object.ComputeHash(input_hash_byte)))%_q;
    group_hash = _g.Pow(group_hash, _p);

    QSharedPointer<Crypto::CppDsaPrivateKey> priv_key =
      _priv_ident.dynamicCast<CppDsaPrivateKey>();

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

    input_hash_byte = GetPublicIdentByteArray() + linkage_tag + message +
      _g.Pow(u, _p).GetByteArray() + group_hash.Pow(u, _p).GetByteArray();

    hash_object.Restart();
    Integer b = Integer(hash_object.ComputeHash(input_hash_byte));

    ci[(_self_identity + 1) % _num_members] = b;
    qDebug() << "self_ident: " << _self_identity;
    qDebug() << "Reached Here!";

    for(int i = (_self_identity + 1) % _num_members; i != _self_identity;
         i = (i + 1)%_num_members)
    {
      rng->GenerateBlock(random_byte_array);

      si[i] = (Integer(random_byte_array)%_q);

      QSharedPointer<Crypto::CppDsaPublicKey> publ_k =
        _public_ident[i].dynamicCast<CppDsaPublicKey>();

      input_hash_byte = GetPublicIdentByteArray() + linkage_tag + message +
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

}
}
}

