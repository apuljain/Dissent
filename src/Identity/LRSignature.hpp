#ifndef DISSENT_IDENTITY_LRS_SIGNATURE_H_GUARD
#define DISSENT_IDENTITY_LRS_SIGNATURE_H_GUARD

#include <QMetaType>
#include "Crypto/Integer.hpp"

namespace Dissent {
namespace Identity {
  /**
   * Signature class. It holds LR Signature components.
   */
  class LRSignature : public QObject {
    Q_OBJECT

    public:
      typedef Crypto::Integer Integer;

      virtual ~LRSignature() {}

      LRSignature() {}

      /**
       * Constructor to initialize signature object.
       * @param: signature components.
       */
      explicit LRSignature(const Integer &c, const QVector<Integer> &s, const Integer &tag):
      _c(c), _linkage_tag(tag), _s(s)
      {
      }

      inline Integer GetC() {return _c;}

      inline QVector<Integer> GetS() {return _s;}

      inline Integer& GetSi(const int &index) {return _s[index];}

      inline Integer& GetTag() {return _linkage_tag;}

      void SetTag(const Integer &tag) {_linkage_tag = tag;}

      void SetC(const Integer &c) {_c = c;}

      void SetS(QVector<Integer> &s)
      {
        _s.clear();
        for(QVector<Integer>::const_iterator itr = s.begin(); itr != s.end(); itr++)
        {
          _s.push_back(*itr);
        }
      }

    private:
      Integer _c, _linkage_tag;
      QVector<Integer> _s;
   };
 }
}
Q_DECLARE_METATYPE(QSharedPointer<Dissent::Identity::LRSignature>)
#endif
