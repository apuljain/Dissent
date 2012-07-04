#ifndef DISSENT_IDENTITY_LRS_SIGNATURE_H_GUARD
#define DISSENT_IDENTITY_LRS_SIGNATURE_H_GUARD

#include "Crypto/Integer.hpp"

namespace Dissent {
namespace Identity {

  class LRSignature {

    private:

      const Integer _c, _linkage_tag;
      const QVector<Integer> _s;

    public:

      typedef Crypto::Integer Integer;

      /**
       * Constructor to initialize signature object.
       * @param: signature components.
       */
      explicit LRSignature(const Integer &c, const QVector<Integer> &s,
                           const Integer &tag):
      _c(c), _linkage_tag(tag), _s(s)
      {
      }

      inline const Integer &GetC() {return _c;}

      inline const QVector<Integer> &GetS() {return _s;}

      inline const Integer &GetSi(const int &index) {return _s[index];}

      inline const Integer &GetTag() {return _linkage_tag;}

      void SetTag(const Integer &tag) {_linkage_tag = tag;}

      void SetC(const Integer &c) {_c = c;}

      void SetS(const QVector<Integer> &s) {_s = s;}
   };
}
}
#endif
