#ifndef DISSENT_TESTS_MOCK_EDGE_HANDLER_H_GUARD
#define DISSENT_TESTS_MOCK_EDGE_HANDLER_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  class MockEdgeHandler : public QObject {
    Q_OBJECT

    public:
      explicit MockEdgeHandler(EdgeListener *el)
      {
        QObject::connect(el, SIGNAL(NewEdge(QSharedPointer<Edge>)),
            this, SLOT(HandleEdge(QSharedPointer<Edge>)));
      }

      virtual ~MockEdgeHandler() {}
      QSharedPointer<Edge> edge;

    private slots:
      void HandleEdge(QSharedPointer<Edge> edge)
      {
        this->edge = edge;
      }
  };
}
}
#endif
