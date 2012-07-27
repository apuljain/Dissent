#include "LRSAuthenticator.hpp"
#include "LRVerifier.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  LRSAuthenticator::LRSAuthenticator(
    const QVector<QSharedPointer<PublicIdentity> > &public_ident):
    _public_ident(public_ident)
  {
  }

  QPair<bool, PublicIdentity> LRSAuthenticator::VerifyResponse(
    const Connections::Id &member, const QVariant &data)
  {
    QByteArray _context_tag(10,'a');
    QByteArray _message(10, 'b');

    QVariantList response = data.toList();
    if(response.count() != 2)
    {
      qDebug() << "Received invalid response";
      return QPair<bool, PublicIdentity> (false, PublicIdentity());
    }

    QByteArray ident_byte = response[0].toByteArray();
    QDataStream stream(ident_byte);
    PublicIdentity ident;
    stream >> ident;

    if(ident.GetId() != member)
    {
      qDebug() << "Invalid Id";
      return QPair<bool, PublicIdentity> (false, PublicIdentity());
    }

    QVariant signature = response[1];

    //store tags and corresponding public_ident
    QList<QVariant> in;
    in = signature.toList();
    QByteArray tag = in[2].toByteArray();

    //Check for double authentication.
    //FIXME: Policy decision - what to do if a client tries to authenticate twice.
    if(_tag_public_idents.contains(tag))
    {
      qDebug() << "Client already authenticated.";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    _tag_public_idents[tag] = ident_byte;

    QVector<QSharedPointer<AsymmetricKey> > _public_ident_asymm;

    //Get Asymmetric keys from public_idents.
    for(QVector<QSharedPointer<PublicIdentity> >::const_iterator itr =
        _public_ident.begin(); itr != _public_ident.end(); ++itr)
    {
      _public_ident_asymm.push_back((*itr)->GetVerificationKey());
    }

    LRVerifier autho(_public_ident_asymm, _context_tag);
    if(!autho.LRVerify(_message, signature))
    {
      qDebug() << "Invalid signature";
      return QPair<bool, PublicIdentity>(false, PublicIdentity());
    }

    return (QPair<bool, PublicIdentity>(true, ident));
  }

}
}
}
