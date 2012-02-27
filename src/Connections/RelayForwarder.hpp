#ifndef DISSENT_CONNECTIONS_RELAY_FORWARDER_H_GUARD
#define DISSENT_CONNECTIONS_RELAY_FORWARDER_H_GUARD

#include <QObject>
#include <QStringList>

#include "Messaging/ISender.hpp"
#include "Messaging/RpcHandler.hpp"

#include "ConnectionTable.hpp"

namespace Dissent {
namespace Messaging {
  class Request;
}

namespace Connections {
  /**
   * Does the hard work in forwarding packets over the overlay
   */
  class RelayForwarder : public QObject {
    Q_OBJECT

    public:
      typedef Dissent::Messaging::ISender ISender;
      typedef Dissent::Messaging::Request Request;
      typedef Dissent::Messaging::RpcHandler RpcHandler;

      /**
       * Constructor
       * @param local_id the id of the source node
       * @param ct list of potential forwarders
       * @param rpc rpc communication helper
       */
      RelayForwarder(const Id &local_id, const ConnectionTable &ct,
          const QSharedPointer<RpcHandler> &rpc);
  
      /**
       * Destructor
       */
      virtual ~RelayForwarder();

      /**
       * Returns a sender that can be used to communicate via the overlay
       */
      QSharedPointer<ISender> GetSender(const Id &to);

      /**
       * The forwarding sender should call this to forward a message along
       */
      virtual void Send(const Id &to, const QByteArray &data);

      QSharedPointer<RelayForwarder> GetSharedPointer()
      {
         return _shared.toStrongRef();
      }

      void SetSharedPointer(const QSharedPointer<RelayForwarder> &shared)
      {
        _shared = shared.toWeakRef();
      }

    private:
      /**
       * Helper function for forwarding data -- does the hard work
       */
      void Forward(const Id &to, const QByteArray &data,
          const QStringList &been);

      const Id _local_id;
      const QStringList _base_been;
      const ConnectionTable &_ct;
      QSharedPointer<RpcHandler> _rpc;
      static const Id _prefered;
      QWeakPointer<RelayForwarder> _shared;
      
    private slots:
      /**
       * Incoming data for forwarding
       */
      virtual void IncomingData(const Request &notification);

  };
}
}

#endif
