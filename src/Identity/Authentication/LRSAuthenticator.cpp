#include "LRSAuthenticator.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSAuthenticator::LRSAuthenticator(
    const QVector<QSharedPointer<PublicIdentity> > &public_ident,
    Integer &g, Integer &p, Integer &q):
    _public_ident(public_ident),
    _g(g), _p(p), _q(q)
  {
    _num_members = public_ident.count();
  }

  const QByteArray LRSAuthenticator::GetPublicIdentByteArray()
  {
    QByteArray value;

    for(QVector<QSharedPointer<PublicIdentity> >::const_iterator itr =
      _public_ident.begin();
      itr != _public_ident.end(); ++itr)
    {
      QSharedPointer<Crypto::CppDsaPublicKey> publ_k =
       (*itr)->GetVerificationKey().dynamicCast<CppDsaPublicKey>();
      value.append(publ_k->GetPublicElement().GetByteArray());
    }
    return value;
  }

  QPair<bool, PublicIdentity> LRSAuthenticator::VerifyResponse(
    const Connections::Id &member, const QVariant &data)
  {
    const QPair<bool, PublicIdentity> invalid(false, PublicIdentity());

    if(!data.canConvert<QSharedPointer<LRSignature> >())
    {
      qWarning() << "Got Invalid Signature data: Cannot convert to LRSignature";
      return invalid;
    }

    QSharedPointer<LRSignature> signature =
      data.value<QSharedPointer<LRSignature> >();

    _num_members = _public_ident.count();

    //prepare input byte array - public_identities.
    QByteArray input_hash_byte = GetPublicIdentByteArray();

    //Calculate hash = H(public_keys) and map it to an element in the group.
    Dissent::Crypto::CppHash hash_object;
    Integer group_hash = (Integer(hash_object.ComputeHash(input_hash_byte))%_q);
    group_hash = _g.Pow(group_hash, _p);

    Integer zi, zi_dash;
    Integer ci = signature->GetC();

    for(int i = 0; i < _num_members; i++)
    {
      QSharedPointer<Crypto::CppDsaPublicKey> publ_k =
       _public_ident[i]->GetVerificationKey().dynamicCast<CppDsaPublicKey>();

      zi = (_g.Pow(signature->GetSi(i), _p) *
            (publ_k->GetPublicElement().Pow(ci, _p))) % _p;

      zi_dash = ((group_hash.Pow(signature->GetSi(i), _p)) *
                  (signature->GetTag().Pow(ci, _p))) % _p;

      //prepare input hash string
      input_hash_byte = GetPublicIdentByteArray() +
        signature->GetTag().GetByteArray() +
        zi.GetByteArray() + zi_dash.GetByteArray();

      //compute hash
      hash_object.Restart();
      ci = Integer(hash_object.ComputeHash(input_hash_byte));
    }

    return QPair<bool, PublicIdentity> (signature->GetC() == ci, PublicIdentity());
  }
}
}
}
