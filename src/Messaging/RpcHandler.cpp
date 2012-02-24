#include <QDataStream>
#include <QVariant>

#include "RpcHandler.hpp"

namespace Dissent {
namespace Messaging {
  const QString Request::NotificationType = QString("n");
  const QString Request::RequestType = QString("r");
  const QString Response::ResponseType = QString("p");

  RpcHandler::RpcHandler() :
    _current_id(1),
    _responder(new RequestResponder())
  {
    QObject::connect(_responder.data(),
        SIGNAL(RespondSignal(const Request &, const QVariant &)),
        this, SLOT(SendResponse(const Request &, const QVariant &)));

    QObject::connect(_responder.data(),
        SIGNAL(FailedSignal(const Request &, const QString &)),
        this, SLOT(SendFailedResponse(const Request &, const QString &)));
  }

  RpcHandler::~RpcHandler()
  {
  }

  void RpcHandler::HandleData(const QSharedPointer<ISender> &from,
      const QByteArray &data)
  {
    QVariantList container;
    QDataStream stream(data);
    stream >> container;

    if(container.size() < 2) {
      return;
    }

    QString type = container.at(0).toString();
    if(type == Request::RequestType ||
        type == Request::NotificationType)
    {
      HandleRequest(Request(_responder, from, container));
    } else if(type == Response::ResponseType) {
      HandleResponse(Response(from, container));
    } else {
      qDebug() << "Received an unknown Rpc type:" << type;
    }
  }

  void RpcHandler::HandleRequest(const Request &request)
  {
    int id = request.GetId();
    if(id <= 0) {
      qWarning() << "RpcHandler: Request: Invalid ID, from: " <<
        request.GetFrom()->ToString();
      return;
    }

    QString method = request.GetMethod();
    QSharedPointer<RequestHandler> cb = _callbacks[method];
    if(cb.isNull()) {
      qDebug() << "RpcHandler: Request: No such method: " << method <<
        ", from: " << request.GetFrom()->ToString();
      SendFailedResponse(request, QString("No such method: " + method));
      return;
    }

    qDebug() << "RpcHandler: Request: Method:" << method << ", from:" << 
      request.GetFrom()->ToString();
    cb->MakeRequest(request);
  }

  void RpcHandler::HandleResponse(const Response &response)
  {
    int id = response.GetId();
    if(id == 0) {
      qWarning() << "RpcHandler: Response: No ID, from " <<
        response.GetFrom()->ToString();
      return;
    }

    QSharedPointer<ResponseHandler> cb = _requests[id];
    if(cb.isNull()) {
      qWarning() << "RpcHandler: Response: No handler for " << id;
      return;
    }

    _requests.remove(id);

    cb->RequestComplete(response);
  }

  void RpcHandler::SendNotification(const QSharedPointer<ISender> &to,
      const QString &method, const QVariant &data)
  {
    int id = IncrementId();
    QVariantList container = Request::BuildNotification(id, method, data);

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << container;
    to->Send(msg);
  }

  int RpcHandler::SendRequest(const QSharedPointer<ISender> &to,
      const QString &method, const QVariant &data,
      const QSharedPointer<ResponseHandler> &cb)
  {
    int id = IncrementId();
    _requests[id] = cb;
    QVariantList container = Request::BuildRequest(id, method, data);

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << container;
    to->Send(msg);
    return id;
  }

  void RpcHandler::SendResponse(const Request &request, const QVariant &data)
  {
    QVariantList container = Response::Build(request.GetId(), data);
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << container;
    request.GetFrom()->Send(msg);
  }

  void RpcHandler::SendFailedResponse(const Request &request, const QString &reason)
  {
    QVariantList container = Response::Failed(request.GetId(), reason);
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << container;
    request.GetFrom()->Send(msg);
  }

  int RpcHandler::IncrementId()
  {
    int id = _current_id++;
    return id;
  }

  bool RpcHandler::Register(const QString &name,
      const QSharedPointer<RequestHandler> &cb)
  {
    if(_callbacks.contains(name)) {
      return false;
    }

    _callbacks[name] = cb;
    return true;
  }

  bool RpcHandler::Unregister(const QString &name)
  {
    QSharedPointer<RequestHandler> cb = _callbacks.value(name);
    if(cb.isNull()) {
      return false;
    }

    _callbacks.remove(name);
    return true;
  }
}
}
