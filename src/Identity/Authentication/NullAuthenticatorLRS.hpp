#ifndef DISSENT_IDENTITY_NULL_AUTHENTICATOR_LRS_H_GUARD
#define DISSENT_IDENTITY_NULL_AUTHENTICATOR_LRS_H_GUARD

#include <QVariant>
#include <Crypto/Integer.hpp>
#include "Connections/Id.hpp"
#include "Identity/Group.hpp"
#include "IAuthenticatorLRS.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  /**
   * Implements an authenticating agent that always authenticates everyone
   */
  class NullAuthenticatorLRS : public IAuthenticatorLRS {

    public:

      /**
       * Empty constructor.
       */
      NullAuthenticatorLRS() {};

      /**
       * Constructor to initialize parameters.
       * @param: group - it contains all information about group like generators,
       *         roster of public_keys etc.
       */
      NullAuthenticatorLRS(const QSharedPointer<const Group> group_in) :
        _group(group_in), _g(group_in->GetGenerator()), _p(group_in->GetPrime()), _q(group_in->GetOrder()),
        _num_members(group_in->Count())
      {
      }

      virtual ~NullAuthenticatorLRS() {}

      /**
       * Always returns true
       * @param signature component c1
       * @param signature component s
       * @param signature linkage tag
       * @returns returns true
       */
      virtual bool VerifySignature(const Integer &c, const QVector<Integer> &s,
        const Integer linkaga_tag)
      {
        return true;
      }

  private:

    QSharedPointer<const Group> _group;
    const Integer _g, _p, _q;
    int _num_members;
  };
}
}
}

#endif
