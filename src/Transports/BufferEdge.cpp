#include "BufferEdge.hpp"

using Dissent::Utils::TimerCallback;
using Dissent::Utils::Timer;
using Dissent::Utils::TimerMethod;

namespace Dissent {
namespace Transports {
  BufferEdge::BufferEdge(const Address &local, const Address &remote,
      bool outgoing, int delay) :
    Edge(local, remote, outgoing), Delay(delay), _remote_edge(0),
    _rem_closing(false), _incoming(0)
  {
  }

  BufferEdge::~BufferEdge()
  {
  }

  void BufferEdge::SetRemoteEdge(QSharedPointer<BufferEdge> remote_edge)
  {
    if(!_remote_edge.isNull()) {
      qWarning() << "BufferEdge's remote already set.";
      return;
    }
    _remote_edge = remote_edge;
  }

  void BufferEdge::Send(const QByteArray &data)
  {
    if(Stopped()) {
      qWarning() << "Attempted to send on a closed edge.";
      return;
    }

    if(_rem_closing) {
      return;
    }

    TimerCallback *tm = new TimerMethod<BufferEdge, QByteArray>(_remote_edge.data(),
        &BufferEdge::DelayedReceive, data);
    Timer::GetInstance().QueueCallback(tm, Delay);
    _remote_edge->_incoming++;
  }

  void BufferEdge::OnStop()
  {
    Edge::OnStop();

    qDebug() << "Calling Close on " << ToString() << " with " << _incoming << " remaining messages.";
    if(!_rem_closing) {
      _remote_edge->_rem_closing = true;
      _remote_edge.clear();
    }

    if(_incoming == 0) {
      StopCompleted();
    }
  }

  void BufferEdge::DelayedReceive(const QByteArray &data)
  {
    _incoming--;
    if(Stopped()) {
      if(_incoming == 0) {
        qDebug() << "No more messages on calling Edge::Close";
        StopCompleted();
      }
      return;
    }
    PushData(GetSharedPointer(), data);
  }
}
}
