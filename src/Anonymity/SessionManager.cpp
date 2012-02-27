#include "Messaging/Request.hpp"
#include "Messaging/RequestHandler.hpp"
#include "Messaging/RpcHandler.hpp"

#include "Session.hpp"
#include "SessionManager.hpp"

using Dissent::Messaging::RequestHandler;

namespace Dissent {
namespace Anonymity {
  SessionManager::SessionManager(const QSharedPointer<RpcHandler> &rpc) :
    _default_session(Id::Zero()),
    _default_set(false),
    _rpc(rpc)
  {
    QSharedPointer<RequestHandler> reg(
        new RequestHandler(this, "Register"));
    _rpc->Register("SM::Register", reg);

    QSharedPointer<RequestHandler> prepare(
        new RequestHandler(this, "Prepare"));
    _rpc->Register("SM::Prepare", prepare);

    QSharedPointer<RequestHandler> begin(
        new RequestHandler(this, "Begin"));
    _rpc->Register("SM::Begin", begin);

    QSharedPointer<RequestHandler> data(
        new RequestHandler(this, "IncomingData"));
    _rpc->Register("SM::Data", data);
  }

  SessionManager::~SessionManager()
  {
    _rpc->Unregister("SM::Register");
    _rpc->Unregister("SM::Prepare");
    _rpc->Unregister("SM::Begin");
    _rpc->Unregister("SM::Data");
  }

  void SessionManager::AddSession(const QSharedPointer<Session> &session)
  {
    QObject::connect(session.data(), SIGNAL(Stopping()), this, SLOT(HandleSessionStop()));
    _id_to_session[session->GetId()] = session;
    if(!_default_set) {
      _default_set = true;
      _default_session = session->GetId();
    }
  }

  QSharedPointer<Session> SessionManager::GetSession(const Id &id)
  {
    return _id_to_session.value(id);
  }

  void SessionManager::SetDefaultSession(const Id &id)
  {
    if(_id_to_session.contains(id)) {
      _default_set = true;
      _default_session = id;
    }
  }

  QSharedPointer<Session> SessionManager::GetDefaultSession()
  {
    return _id_to_session.value(_default_session);
  }

  void SessionManager::Register(const Request &request)
  {
    QSharedPointer<Session> session = GetSession(request);
    if(!session.isNull()) {
      session->ReceivedRegister(request);
    } else {
      /*
      Dissent::Messaging::RpcContainer response;
      response["result"] = false;
      response["online"] = false;
      request.Respond(response);
      */
    }
  }

  void SessionManager::Prepare(const Request &request)
  {
    QSharedPointer<Session> session = GetSession(request);
    if(!session.isNull()) {
      session->ReceivedPrepare(request);
    } else {
      /*
      Dissent::Messaging::RpcContainer response;
      response["result"] = false;
      response["online"] = false;
      request.Respond(response);
      */
    }
  }

  void SessionManager::Begin(const Request &notification)
  {
    QSharedPointer<Session> session = GetSession(notification);
    if(!session.isNull()) {
      session->ReceivedBegin(notification);
    }
  }

  void SessionManager::IncomingData(const Request &notification)
  {
    QSharedPointer<Session> session = GetSession(notification);
    if(!session.isNull()) {
      session->IncomingData(notification);
    }
  }

  QSharedPointer<Session> SessionManager::GetSession(const Request &msg)
  {
    QByteArray bid = msg.GetData().toHash().value("session_id").toByteArray();
    if(bid.isEmpty()) {
      qWarning() << "Received a wayward session message from " <<
        msg.GetFrom()->ToString();
      return QSharedPointer<Session>();
    }

    Id id(bid);
    if(_id_to_session.contains(id)) {
      return _id_to_session[id];
    } else {
      qWarning() << "Received a wayward session message for session " <<
        id.ToString() << " from " << msg.GetFrom()->ToString();
      return QSharedPointer<Session>();
    }
  }

  void SessionManager::HandleSessionStop()
  {
    Session *session = qobject_cast<Session *>(sender());
    if(!session) {
      qCritical() << "Expected session found null";
      return;
    }

    QObject::disconnect(session, SIGNAL(Stopping()), this, SLOT(HandleSessionStop()));
    _id_to_session.remove(session->GetId());
  }
}
}
