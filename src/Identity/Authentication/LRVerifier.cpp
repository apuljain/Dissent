#include "LRVerifier.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRVerifier::LRVerifier(
    const QVector<QSharedPointer<PublicIdentity> > &public_ident,
    const QByteArray &context_tag,
    const Integer &g, const Integer &p, const Integer &q):
    _public_ident(public_ident), _context_tag(context_tag),
    _g(g), _p(p), _q(q)
  {
  }

  const QByteArray LRVerifier::GetPublicIdentByteArray()
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

  QPair<bool, PublicIdentity> LRVerifier::LRVerify(
    const QByteArray &message, const Id &member, const QVariant &data)
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
    QByteArray input_hash_byte = GetPublicIdentByteArray() + _context_tag;

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
      input_hash_byte = GetPublicIdentByteArray() + linkage_tag.GetByteArray() +
        message + zi.GetByteArray() + zi_dash.GetByteArray();

      //compute hash
      hash_object.Restart();
      ci = Integer(hash_object.ComputeHash(input_hash_byte));
    }

    return QPair<bool, PublicIdentity> (Integer(in[0].toByteArray()) == ci, PublicIdentity());
  }

}
}
}

