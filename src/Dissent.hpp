#ifndef DISSENT_DISSENT_H_GUARD
#define DISSENT_DISSENT_H_GUARD

#include "Anonymity/BulkRound.hpp"
#include "Anonymity/Log.hpp"
#include "Anonymity/MessageRandomizer.hpp"
#include "Anonymity/NullRound.hpp"
#include "Anonymity/RepeatingBulkRound.hpp"
#include "Anonymity/Round.hpp"
#include "Anonymity/Session.hpp"
#include "Anonymity/SessionManager.hpp"
#include "Anonymity/ShuffleBlamer.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Anonymity/ShuffleRoundBlame.hpp"
#include "Anonymity/TrustedBulkRound.hpp"
#include "Anonymity/Tolerant/Accusation.hpp"
#include "Anonymity/Tolerant/AlibiData.hpp"
#include "Anonymity/Tolerant/BlameMatrix.hpp"
#include "Anonymity/Tolerant/Conflict.hpp"
#include "Anonymity/Tolerant/MessageHistory.hpp"
#include "Anonymity/Tolerant/TolerantBulkRound.hpp"
#include "Anonymity/Tolerant/TolerantTreeRound.hpp"

#include "Applications/CommandLine.hpp"
#include "Applications/ConsoleSink.hpp"
#include "Applications/FileSink.hpp"
#include "Applications/Node.hpp"
#include "Applications/SessionFactory.hpp"
#include "Applications/Settings.hpp"

#include "ClientServer/CSOverlay.hpp"
#include "ClientServer/CSConnectionAcquirer.hpp"

#include "Connections/Bootstrapper.hpp"
#include "Connections/Connection.hpp"
#include "Connections/ConnectionAcquirer.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Connections/EmptyNetwork.hpp"
#include "Connections/FullyConnected.hpp"
#include "Connections/Id.hpp"
#include "Connections/Network.hpp"
#include "Connections/RelayAddress.hpp"
#include "Connections/RelayEdge.hpp"
#include "Connections/RelayEdgeListener.hpp"

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CppDiffieHellman.hpp"
#include "Crypto/CppHash.hpp"
#include "Crypto/CppIntegerData.hpp"
#include "Crypto/CppLibrary.hpp"
#include "Crypto/CppPrivateKey.hpp"
#include "Crypto/CppPublicKey.hpp"
#include "Crypto/CppRandom.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Crypto/DiffieHellman.hpp"
#include "Crypto/CppHash.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Integer.hpp"
#include "Crypto/IntegerData.hpp"
#include "Crypto/Library.hpp"
#include "Crypto/NullDiffieHellman.hpp"
#include "Crypto/NullHash.hpp"
#include "Crypto/NullLibrary.hpp"
#include "Crypto/NullPrivateKey.hpp"
#include "Crypto/NullPublicKey.hpp"
#include "Crypto/OnionEncryptor.hpp"
#include "Crypto/Serialization.hpp"
#include "Crypto/ThreadedOnionEncryptor.hpp"
#include "Identity/Credentials.hpp"
#include "Identity/Group.hpp"
#include "Identity/GroupHolder.hpp"
#include "Messaging/BufferSink.hpp"
#include "Messaging/DummySink.hpp"
#include "Messaging/Filter.hpp"
#include "Messaging/GetDataCallback.hpp" 
#include "Messaging/ISender.hpp"
#include "Messaging/ISink.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/RequestHandler.hpp"
#include "Messaging/Response.hpp"
#include "Messaging/ResponseHandler.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Messaging/Source.hpp"
/*
#include "Overlay/BaseOverlay.hpp"
#include "Overlay/BasicGossip.hpp"

#include "PeerReview/Acknowledgement.hpp"
#include "PeerReview/Entry.hpp"
#include "PeerReview/EntryParser.hpp"
#include "PeerReview/EntryLog.hpp"
#include "PeerReview/PRManager.hpp"
#include "PeerReview/ReceiveEntry.hpp"
#include "PeerReview/SendEntry.hpp"
*/
#include "Transports/Address.hpp"
#include "Transports/AddressFactory.hpp"
#include "Transports/BufferAddress.hpp"
#include "Transports/BufferEdge.hpp"
#include "Transports/BufferEdgeListener.hpp"
#include "Transports/Edge.hpp"
#include "Transports/EdgeFactory.hpp"
#include "Transports/EdgeListener.hpp"
#include "Transports/EdgeListenerFactory.hpp"
#include "Transports/TcpAddress.hpp"
#include "Transports/TcpEdge.hpp"
#include "Transports/TcpEdgeListener.hpp"

#include "Utils/Logging.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Random.hpp"
#include "Utils/Serialization.hpp"
#include "Utils/SignalCounter.hpp"
#include "Utils/Sleeper.hpp"
#include "Utils/StartStop.hpp"
#include "Utils/StartStopSlots.hpp"
#include "Utils/Time.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"
#include "Utils/TimerEvent.hpp"
#include "Utils/Triggerable.hpp"
#include "Utils/Triple.hpp"
#include "Utils/Utils.hpp"
/*
#include "Web/HttpRequest.hpp"
#include "Web/HttpResponse.hpp"
#include "Web/WebRequest.hpp"
#include "Web/WebServer.hpp"
#include "Web/Packagers/Packager.hpp"
#include "Web/Packagers/JsonPackager.hpp"
#include "Web/Services/GetFileService.hpp"
#include "Web/Services/GetMessagesService.hpp"
#include "Web/Services/MessageWebService.hpp"
#include "Web/Services/RoundIdService.hpp"
#include "Web/Services/SendMessageService.hpp"
#include "Web/Services/SessionIdService.hpp"
#include "Web/Services/SessionWebService.hpp"
#include "Web/Services/WebService.hpp"
*/
using namespace Dissent::Anonymity;
using namespace Dissent::Anonymity::Tolerant;
using namespace Dissent::Applications;
using namespace Dissent::ClientServer;
using namespace Dissent::Connections;
using namespace Dissent::Crypto;
using namespace Dissent::Identity;
using namespace Dissent::Messaging;
using namespace Dissent::Overlay;
using namespace Dissent::Transports;
using namespace Dissent::Utils;
/*
using namespace Dissent::Web;
using namespace Dissent::Web::Services;
using namespace Dissent::Web::Packagers;
*/

#endif
