#ifndef DISSENT_IDENTITY_IAUTHENTICATOR_LRS_H_GUARD
#define DISSENT_IDENTITY_IAUTHENTICATOR_LRS_H_GUARD

#include <QPair>
#include <QVariant>

#include "Connections/Id.hpp"
#include "Crypto/CppHash.hpp"
#include "Identity/Group.hpp"
#include "Crypto/Integer.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

    /**
     * An abstract base class for an authenticator,
     * one to whom others authenticate
     */
  class IAuthenticatorLRS {

    public:
      typedef Connections::Id Id;

      IAuthenticatorLRS() {}

      /**
       * Constructor to initialize parameters.
       * @param: group - it contains all information about group like generators,
       *         roster of public_keys etc.
       */
      IAuthenticatorLRS(QSharedPointer<const Group> group_in) :
        _group(group_in), _g(group_in->GetGenerator()), _p(group_in->GetPrime()), _q(group_in->GetOrder()),
        _num_members(group_in->Count())
      {
      }

      virtual ~IAuthenticatorLRS() {}

      /**
       * Given a signature <c, s1...sn, tag>, it verifies signature.
       * @param signature components <c, s1..sn, tag>
       * @returns returns true if signature is valid else false.
       */
      bool VerifySignature(const Integer &c, const QVector<Integer> &s,
        const Integer linkaga_tag);

    private:

      QSharedPointer<const Group> _group;
      Crypto::Integer _g, _p, _q;
      int _num_members;
  };
}
}
}

#endif
