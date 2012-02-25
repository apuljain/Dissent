#ifndef DISSENT_DUMMY_SINK_H_GUARD
#define DISSENT_DUMMY_SINK_H_GUARD

#include "ISink.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Ignores all input
   */
  class DummySink : public ISink {
    public:
      virtual void HandleData(const QSharedPointer<ISender> &,
          const QByteArray &)
      {
      }

      /**
       * Destructor
       */
      virtual ~DummySink() {}
  };
}
}

#endif
