#include "Anonymity/BulkRound.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Connections/Connection.hpp"
#include "Connections/Network.hpp"
#include "Crypto/DiffieHellman.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Library.hpp"
#include "Crypto/Serialization.hpp"
#include "Messaging/Request.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Random.hpp"
#include "Utils/Serialization.hpp"

#include "TolerantTreeRound.hpp"

using Dissent::Connections::Connection;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::DiffieHellman;
using Dissent::Crypto::Library;
using Dissent::Utils::QRunTimeError;
using Dissent::Utils::Random;
using Dissent::Utils::Serialization;

namespace Dissent {
namespace Anonymity {
namespace Tolerant {
  TolerantTreeRound::TolerantTreeRound(const Group &group,
      const Credentials &creds, const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    Round(group, creds, round_id, network, get_data),
    _is_leader((GetGroup().GetLeader() == GetLocalId())),
    _is_server(GetGroup().GetSubgroup().Contains(GetLocalId())),
    _stop_next(false),
    _secrets_with_servers(GetGroup().GetSubgroup().Count()),
    _rngs_with_servers(GetGroup().GetSubgroup().Count()),
    _get_key_shuffle_data(this, &TolerantTreeRound::GetKeyShuffleData),
    _create_shuffle(create_shuffle),
    _state(State_Offline),
    _crypto_lib(CryptoFactory::GetInstance().GetLibrary()),
    _hash_algo(_crypto_lib->GetHashAlgorithm()),
    _anon_signing_key(_crypto_lib->CreatePrivateKey()),
    _phase(0),
    _user_messages(GetGroup().Count()),
    _server_messages(GetGroup().GetSubgroup().Count()),
    _user_message_digests(GetGroup().Count()),
    _server_message_digests(GetGroup().GetSubgroup().Count()),
    _message_randomizer(creds.GetDhKey()->GetPrivateComponent()),
    _user_idx(GetGroup().GetIndex(GetLocalId()))
  {
    qDebug() << "Leader:" << _is_leader << "LocID" << GetLocalId().ToString() 
      << "LeadID" << GetGroup().GetLeader().ToString();

    QVariantHash headers = GetNetwork()->GetHeaders();
    headers["round"] = Header_Bulk;
    GetNetwork()->SetHeaders(headers);

    // Get shared secrets with servers
    const Group servers = GetGroup().GetSubgroup();
    for(int server_idx=0; server_idx<servers.Count(); server_idx++) {
      QByteArray server_pk = servers.GetPublicDiffieHellman(server_idx);
      QByteArray secret = creds.GetDhKey()->GetSharedSecret(server_pk);

      _secrets_with_servers[server_idx] = secret;
      _rngs_with_servers[server_idx] = QSharedPointer<Random>(_crypto_lib->GetRandomNumberGenerator(secret));
    }

    // Set up shared secrets
    if(_is_server) {
      _secrets_with_users.resize(GetGroup().Count());
      _rngs_with_users.resize(GetGroup().Count());
      _server_idx = GetGroup().GetSubgroup().GetIndex(GetLocalId());

      // Get shared secrets with users
      const Group users = GetGroup();
      for(int user_idx=0; user_idx<users.Count(); user_idx++) {
        QByteArray user_pk = users.GetPublicDiffieHellman(user_idx);
        QByteArray secret = creds.GetDhKey()->GetSharedSecret(user_pk);

        _secrets_with_users[user_idx] = secret;
        _rngs_with_users[user_idx] = QSharedPointer<Random>(_crypto_lib->GetRandomNumberGenerator(secret));
      }
    }

    // Set up signing key shuffle
    QSharedPointer<Network> net(GetNetwork()->Clone());
    headers["round"] = Header_SigningKeyShuffle;
    net->SetHeaders(headers);

    Id sr_id(_hash_algo->ComputeHash(GetRoundId().GetByteArray()));

    _key_shuffle_round = _create_shuffle(GetGroup(), GetCredentials(), sr_id,
        net, _get_key_shuffle_data);
    _key_shuffle_round->SetSink(&_key_shuffle_sink);

    QObject::connect(_key_shuffle_round.data(), SIGNAL(Finished()),
        this, SLOT(KeyShuffleFinished()));
  }

  bool TolerantTreeRound::Start()
  {
    if(!Round::Start()) {
      return false;
    }

    ChangeState(State_SigningKeyShuffling);
    _key_shuffle_round->Start();

    return true;
  }

  void TolerantTreeRound::FoundBadMembers() 
  {
    SetSuccessful(false);
    _offline_log.Clear();
    ChangeState(State_Finished);
    Stop("Found bad group member");
    return;
  }

  void TolerantTreeRound::IncomingData(const Request &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }
      
    QSharedPointer<Connection> con = notification.GetFrom().dynamicCast<Connection>();
    if(!con) {
      qDebug() << ToString() << " received wayward message from: " <<
        notification.GetFrom()->ToString();
      return;
    }

    const Id &id = con->GetRemoteId();
    if(!GetGroup().Contains(id)) {
      qDebug() << ToString() << " received wayward message from: " << 
        notification.GetFrom()->ToString();
      return;
    }

    QVariantHash msg = notification.GetData().toHash();
    int round = msg.value("round").toInt();
    switch(round) {
      case Header_Bulk:
        ProcessData(id, msg.value("data").toByteArray());
        break;
      case Header_SigningKeyShuffle:
        qDebug() << "Signing key msg";
        _key_shuffle_round->IncomingData(notification);
        break;
      default:
        qWarning() << "Got message with unknown round header:" << round;
    }
  }

  void TolerantTreeRound::ProcessData(const Id &from, const QByteArray &data)
  {
    _log.Append(data, from);
    try {
      ProcessDataBase(from, data);
    } catch (QRunTimeError &err) {
      qWarning() << _user_idx << GetLocalId().ToString() <<
        "received a message from" << GetGroup().GetIndex(from) << from.ToString() <<
        "in session / round" << GetRoundId().ToString() << "in state" <<
        StateToString(_state) << "causing the following exception: " << err.What();
      _log.Pop();
      return;
    }
  }

  void TolerantTreeRound::ProcessDataBase(const Id &from, const QByteArray &data)
  {
    QByteArray payload;
    if(!Verify(from, data, payload)) {
      throw QRunTimeError("Invalid signature or data");
    }

    if(_state == State_Offline) {
      throw QRunTimeError("Should never receive a message in the bulk"
          " round while offline.");
    }

    QDataStream stream(payload);

    int mtype;
    QByteArray round_id;
    uint phase;
    stream >> mtype >> round_id >> phase;

    MessageType msg_type = static_cast<MessageType>(mtype);

    Id rid(round_id);
    if(rid != GetRoundId()) {
      throw QRunTimeError("Not this round: " + rid.ToString() + " " +
          GetRoundId().ToString());
    }

    // Cache messages for future states in the offline log
    if(!ReadyForMessage(msg_type)) {
      _log.Pop();
      _offline_log.Append(data, from);
      return;
    }

    if(_phase != phase) {
      throw QRunTimeError("Received a message for phase: " + 
          QString::number(phase) + ", while in phase: " +
          QString::number(_phase));
    }

    switch(msg_type) {
      case MessageType_UserCommitData:
        HandleUserCommitData(stream, from);
        break;
      case MessageType_ServerCommitData:
        HandleServerCommitData(stream, from);
        break;
      case MessageType_LeaderCommitData:
        HandleLeaderCommitData(stream, from);
        break;
      case MessageType_UserBulkData:
        HandleUserBulkData(payload, stream, from);
        break;
      case MessageType_ServerBulkData:
        HandleServerBulkData(payload, stream, from);
        break;
      case MessageType_LeaderBulkData:
        HandleLeaderBulkData(stream, from);
        break;
      default:
        throw QRunTimeError("Unknown message type");
    }

  }

  QPair<QByteArray, bool> TolerantTreeRound::GetKeyShuffleData(int)
  {
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    QSharedPointer<AsymmetricKey> pub_key(_anon_signing_key->GetPublicKey());
    stream << pub_key;
    _key_shuffle_data = msg;
    return QPair<QByteArray, bool>(msg, false);
  }

  QSharedPointer<TolerantTreeRound::AsymmetricKey> TolerantTreeRound::ParseSigningKey(const QByteArray &bdes)
  {
    QDataStream stream(bdes);
    QSharedPointer<AsymmetricKey> key_pub;
    stream >> key_pub;

    if(!key_pub->IsValid()) {
      qWarning() << "Received an invalid signing key during the shuffle.";
    }

    return key_pub;
  }

  void TolerantTreeRound::SendCommits()
  {
    ChangeState(_is_leader ? State_CommitSharing : State_CommitReceiving);

    qDebug() << "--";
    qDebug() << "-- NEXT PHASE :" << _phase;
    qDebug() << "--";

    // Get the next data packet
    QByteArray user_xor_msg = GenerateUserXorMessage();
    QDataStream user_data_stream(&_user_next_packet, QIODevice::WriteOnly);
    user_data_stream << MessageType_UserBulkData << GetRoundId() << _phase << user_xor_msg;

    // Commit to next data packet
    QByteArray user_commit_packet;
    QByteArray user_digest = _hash_algo->ComputeHash(_user_next_packet);
    QDataStream user_commit_stream(&user_commit_packet, QIODevice::WriteOnly);
    user_commit_stream << MessageType_UserCommitData << GetRoundId() << _phase << user_digest;
    VerifiableSendToLeader(user_commit_packet);

    if(_is_server) {
      // Get the next data packet
      QByteArray server_xor_msg = GenerateServerXorMessage();
      QDataStream server_data_stream(&_server_next_packet, QIODevice::WriteOnly);
      server_data_stream << MessageType_ServerBulkData << GetRoundId() << _phase << server_xor_msg;

      // Commit to next data packet
      QByteArray server_commit_packet;
      QByteArray server_digest = _hash_algo->ComputeHash(_server_next_packet);
      QDataStream server_commit_stream(&server_commit_packet, QIODevice::WriteOnly);
      server_commit_stream << MessageType_ServerCommitData << GetRoundId() << _phase << server_digest;
      VerifiableSendToLeader(server_commit_packet);
    }
  }

  void TolerantTreeRound::HandleUserCommitData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received user commit data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != State_CommitSharing) {
      throw QRunTimeError("Received a misordered UserCommitData message");
    }

    if(!_is_leader) {
      throw QRunTimeError("Non-leader received a UserCommitData message");
    }

    uint idx = GetGroup().GetIndex(from);
    if(!_user_commits[idx].isEmpty()) {
      throw QRunTimeError("Already have bulk commit data.");
    }

    QByteArray payload;
    stream >> payload;

    const int hash_len = _hash_algo->GetDigestSize();

    if(payload.size() != hash_len) {
      throw QRunTimeError("Incorrect bulk commit message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(hash_len));
    }

    _user_commits[idx] = payload;
    _received_user_commits++;

    if(HasAllCommits()) {
      FinishCommitPhase();
    }
  }

  void TolerantTreeRound::HandleServerCommitData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received server commit data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != State_CommitSharing) {
      throw QRunTimeError("Received a misordered ServerCommitData message");
    }

    if(!_is_leader) {
      throw QRunTimeError("Non-leader received a ServerCommitData message");
    }

    uint idx = GetGroup().GetSubgroup().GetIndex(from);
    if(!_server_commits[idx].isEmpty()) {
      throw QRunTimeError("Already have server bulk commit data.");
    }

    QByteArray payload;
    stream >> payload;

    const int hash_len = _hash_algo->GetDigestSize();

    if(payload.size() != hash_len) {
      throw QRunTimeError("Incorrect server bulk commit message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(hash_len));
    }

    _server_commits[idx] = payload;
    _received_server_commits++;

    if(HasAllCommits()) {
      FinishCommitPhase();
    }
  }

  bool TolerantTreeRound::HasAllCommits()
  {
    return (_received_user_commits == static_cast<uint>(GetGroup().Count()) &&
        _received_server_commits == static_cast<uint>(GetGroup().GetSubgroup().Count()));
  }

  void TolerantTreeRound::FinishCommitPhase()
  {
    qDebug() << "LEADER has all commits";
    ChangeState(State_CommitReceiving);

    _hash_algo->Restart();
    for(int user_idx=0; user_idx<_user_commits.count(); user_idx++) {
      _hash_algo->Update(_user_commits[user_idx]);
    }

    for(int server_idx=0; server_idx<_server_commits.count(); server_idx++) {
      _hash_algo->Update(_server_commits[server_idx]);
    }

    QByteArray leader_digest = _hash_algo->ComputeHash();

    QByteArray leader_commit_packet;
    QDataStream leader_commit_stream(&leader_commit_packet, QIODevice::WriteOnly);
    leader_commit_stream << MessageType_LeaderCommitData << GetRoundId() << _phase << leader_digest;

    VerifiableBroadcast(leader_commit_packet);
  }

  void TolerantTreeRound::HandleLeaderCommitData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received leader commit data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != State_CommitReceiving) {
      throw QRunTimeError("Received a misordered LeaderCommitData message");
    }

    if(from != GetGroup().GetLeader()) {
      throw QRunTimeError("Received a LeaderCommitData message from a non-leader");
    }

    QByteArray payload;
    stream >> payload;

    const int hash_len = _hash_algo->GetDigestSize();

    if(payload.size() != hash_len) {
      throw QRunTimeError("Incorrect leader commit message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(hash_len));
    }

    // Right now we have no way to verify the leader's commit message,
    // so we just continue to the data transmission phase once we
    // get the leader's commit message
    ChangeState(_is_leader ? State_DataSharing : State_DataReceiving);

    VerifiableSendToLeader(_user_next_packet);
    if(_is_server) {
      VerifiableSendToLeader(_server_next_packet);
    }

  }

  void TolerantTreeRound::HandleUserBulkData(const QByteArray &packet, QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received bulk user data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != State_DataSharing) {
      throw QRunTimeError("Received a misordered UserBulkData message");
    }

    if(!_is_leader) {
      throw QRunTimeError("Non-leader received a UserBulkData message");
    }

    uint idx = GetGroup().GetIndex(from);
    if(!_user_messages[idx].isEmpty()) {
      throw QRunTimeError("Already have bulk user data.");
    }

    QByteArray payload;
    stream >> payload;

    if(static_cast<uint>(payload.size()) != _expected_bulk_size) {
      throw QRunTimeError("Incorrect bulk user message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(_expected_bulk_size));
    }

    _user_messages[idx] = payload;
    _user_message_digests[idx] = _hash_algo->ComputeHash(packet);

    _received_user_messages++;
    if(HasAllDataMessages()) {
      BroadcastXorMessages();
    }
  }

  void TolerantTreeRound::HandleServerBulkData(const QByteArray &packet, QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received bulk server data from " << GetGroup().GetSubgroup().GetIndex(from) << from.ToString();

    if(_state != State_DataSharing) {
      throw QRunTimeError("Received a misordered ServerBulkData message");
    }

    if(!_is_leader) {
      throw QRunTimeError("Non-leader received a ServerBulkData message");
    }

    uint idx = GetGroup().GetSubgroup().GetIndex(from);
    if(!_server_messages[idx].isEmpty()) {
      throw QRunTimeError("Already have bulk server data.");
    }

    QByteArray payload;
    stream >> payload;

    if(static_cast<uint>(payload.size()) != _expected_bulk_size) {
      throw QRunTimeError("Incorrect bulk server message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(_expected_bulk_size));
    }

    _server_messages[idx] = payload;
    _server_message_digests[idx] = _hash_algo->ComputeHash(packet);

    qDebug() << "Received server" << _received_server_messages; 

    _received_server_messages++;
    if(HasAllDataMessages()) {
      BroadcastXorMessages();
    }
  }

  bool TolerantTreeRound::HasAllDataMessages() 
  {
    return (_received_user_messages == static_cast<uint>(GetGroup().Count()) &&
        _received_server_messages == static_cast<uint>(GetGroup().GetSubgroup().Count()));
  }

  void TolerantTreeRound::BroadcastXorMessages() 
  {
    ChangeState(State_DataReceiving);

    QByteArray xor_data = XorMessages();

    QByteArray leader_data_packet;
    QDataStream leader_data_stream(&leader_data_packet, QIODevice::WriteOnly);
    leader_data_stream << MessageType_LeaderBulkData << GetRoundId() << _phase << xor_data;
    VerifiableBroadcast(leader_data_packet);
  }

  QByteArray TolerantTreeRound::XorMessages() 
  {
    QByteArray cleartext(_expected_bulk_size, 0);

    for(int idx=0; idx<_user_messages.count(); idx++) {
      Xor(cleartext, cleartext, _user_messages[idx]);
    }

    for(int idx=0; idx<_server_messages.count(); idx++) {
      Xor(cleartext, cleartext, _server_messages[idx]);
    }

    return cleartext;
  }

  void TolerantTreeRound::ProcessMessages(const QByteArray &input)
  {
    const uint size = GetGroup().Count();

    uint msg_idx = 0;
    for(uint slot_idx = 0; slot_idx < size; slot_idx++) {
      int length = _message_lengths[slot_idx] + _header_lengths[slot_idx];
      QByteArray tcleartext = input.mid(msg_idx, length);
      QByteArray msg = ProcessMessage(tcleartext, slot_idx);
      if(!msg.isEmpty()) {
        PushData(GetSharedPointer(), msg);
      }
      msg_idx += length;
    }
  }

  void TolerantTreeRound::CheckCommits(const QVector<QByteArray> &commits, const QVector<QByteArray> &digests,
      QVector<int> &bad)
  {
    if(commits.count() != digests.count()) {
      qFatal("Commits and messages vectors must have same length");
    }

    bad.clear();
    const int len = commits.count();
    for(int idx=0; idx<len; idx++) {
      if(commits[idx] != digests[idx]) {
        bad.append(idx);
      }
    }
  }

  QByteArray TolerantTreeRound::ProcessMessage(const QByteArray &slot_string, uint member_idx)
  {
    QSharedPointer<AsymmetricKey> verification_key(_slot_signing_keys[member_idx]);
    uint vkey_size = verification_key->GetKeySize() / 8;

    // Remove message randomization
    QByteArray cleartext = _message_randomizer.Derandomize(slot_string);

    QByteArray base = cleartext.mid(0, cleartext.size() - vkey_size - 1);
    QByteArray sig = cleartext.mid(cleartext.size() - vkey_size - 1, vkey_size);
   
    /*
    // Shuffle byte is the last byte in the randomized string
    char shuffle_byte = cleartext[cleartext.size()-1];
    bool is_my_message = _anon_signing_key->VerifyKey(*verification_key);
    */

    //qDebug() << "Slot" << slot_string.count() << "Clear" << cleartext.count() << "base" << base.count();

    // Verify the signature before doing anything
    if(verification_key->Verify(base, sig)) {
      uint found_phase = Serialization::ReadInt(cleartext, 0);
      if(found_phase != _phase) {
        qWarning() << "Received a message for an invalid phase:" << found_phase;
        return QByteArray();
      }

      _message_lengths[member_idx] = Serialization::ReadInt(cleartext, 4);

      qDebug() << "Found a message ... PUSHING!";
      return base.mid(8);
    } 

    // What to do if sig doesn't verify
    qWarning() << "Verification failed for message of length" << (base.size()-8) << "for slot owner" << member_idx;
    SetSuccessful(false);
    Stop("Round failed");
    return QByteArray();
  }

  QByteArray TolerantTreeRound::SignMessage(const QByteArray &message)
  {
    return _anon_signing_key->Sign(message);
  }

  QByteArray TolerantTreeRound::GenerateMyCleartextMessage()
  {

    QPair<QByteArray, bool> pair = GetData(4096);

    const QByteArray cur_msg = _next_msg;
    _next_msg = pair.first;
    qDebug() << "GetData(4096) =" << _next_msg;

    QByteArray cleartext(8, 0);
    Serialization::WriteInt(_phase, cleartext, 0);
    Serialization::WriteInt(_next_msg.size(), cleartext, 4);
    cleartext.append(cur_msg);

    QByteArray sig = SignMessage(cleartext);
    
    cleartext.append(sig);

    /* The shuffle byte */
    cleartext.append('\0');

    _last_msg_cleartext = cleartext;
    
    QByteArray randomized = _message_randomizer.Randomize(cleartext);
    _last_msg = randomized;

    qDebug() << "RANDOMIZED:" << randomized.count();
    return randomized;
  }

  QByteArray TolerantTreeRound::GeneratePadWithServer(uint server_idx, uint length)
  {
    QByteArray server_pad(length, 0);
    //qDebug() << "Bytes generated with server" << server_idx << "=" << _rngs_with_servers[server_idx]->BytesGenerated();
    _rngs_with_servers[server_idx]->GenerateBlock(server_pad);
    return server_pad;
  }

  QByteArray TolerantTreeRound::GeneratePadWithUser(uint user_idx, uint length)
  {
    QByteArray user_pad(length, 0);
    //qDebug() << "Bytes generated with server" << server_idx << "=" << _rngs_with_servers[server_idx]->BytesGenerated();
    _rngs_with_users[user_idx]->GenerateBlock(user_pad);
    return user_pad;
  }

  QByteArray TolerantTreeRound::GenerateUserXorMessage()
  {
    QByteArray msg;
    uint size = static_cast<uint>(_slot_signing_keys.size());

    /* For each slot */
    for(uint idx = 0; idx < size; idx++) {
      uint length = _message_lengths[idx] + _header_lengths[idx];
      QByteArray slot_msg(length, 0);
      //qDebug() << "=> STORE BYTES Phase" << _phase << " Slot" << idx << "Bytes=" << _rngs_with_servers[0]->BytesGenerated();

      /* For each server, XOR that server's pad with the empty message */
      for(int server_idx = 0; server_idx < _rngs_with_servers.count(); server_idx++) {
        QByteArray server_pad = GeneratePadWithServer(server_idx, length);
        Xor(slot_msg, slot_msg, server_pad);
      }
      qDebug() << "slot" << idx;

      /* This is my slot */
      if(idx == _my_idx) {
        QByteArray my_msg = GenerateMyCleartextMessage();
        Xor(slot_msg, slot_msg, my_msg);
      }

      msg.append(slot_msg);
      //qDebug() << "XOR length" << msg.count();
    }

    return msg;
  }

  QByteArray TolerantTreeRound::GenerateServerXorMessage()
  {
    QByteArray msg;
    uint size = static_cast<uint>(_slot_signing_keys.size());

    // For each slot 
    for(uint idx = 0; idx < size; idx++) {
      const uint length = _message_lengths[idx] + _header_lengths[idx];
      
      QByteArray slot_msg(length, 0);
      // For each user, XOR that users pad with the empty message
      for(int user_idx = 0; user_idx < _rngs_with_users.count(); user_idx++) {
        QByteArray user_pad = GeneratePadWithUser(user_idx, length);
        Xor(slot_msg, slot_msg, user_pad);
      }
      
      msg.append(slot_msg);
      qDebug() << "XOR length" << msg.count();
    }

    return msg;
  }

  void TolerantTreeRound::HandleLeaderBulkData(QDataStream &stream, const Id &from)
  {
    qDebug() << _user_idx << GetLocalId().ToString() <<
      ": received leader bulk data from " << GetGroup().GetIndex(from) << from.ToString();

    if(_state != State_DataReceiving) {
      throw QRunTimeError("Received a misordered LeaderBulkData message");
    }

    if(from != GetGroup().GetLeader()) {
      throw QRunTimeError("Received a LeaderBulkData message from a non-leader");
    }

    QByteArray payload;
    stream >> payload;

    if(static_cast<uint>(payload.size()) != _expected_bulk_size) {
      throw QRunTimeError("Incorrect leader bulk message length, got " +
          QString::number(payload.size()) + " expected " +
          QString::number(_expected_bulk_size));
    }

    // Split up messages into various slots
    ProcessMessages(payload);

    if(_state == State_Finished) {
      return;   
    }

    if(_stop_next) {
      SetInterrupted();
      Stop("Peer joined"); 
      return;
    }

    PrepForNextPhase();
    _phase++;
    SendCommits();
  }

  void TolerantTreeRound::PrepForNextPhase()
  {
    uint group_size = static_cast<uint>(GetGroup().Count());

    _user_commits.clear();
    _user_commits.resize(group_size);
    _received_user_commits = 0;

    _server_commits.clear();
    _server_commits.resize(GetGroup().GetSubgroup().Count());
    _received_server_commits = 0;

    _user_messages.clear();
    _user_message_digests.clear();
    _user_messages.resize(group_size);
    _user_message_digests.resize(group_size);
    _received_user_messages = 0;

    _server_messages.clear();
    _server_message_digests.clear();
    _server_messages.resize(GetGroup().GetSubgroup().Count());
    _server_message_digests.resize(GetGroup().GetSubgroup().Count());
    _received_server_messages = 0;

    _expected_bulk_size = 0;
    for(uint idx = 0; idx < group_size; idx++) {
      _expected_bulk_size += _header_lengths[idx] + _message_lengths[idx];
    }
  }


  void TolerantTreeRound::AddBadMember(int member_idx) {
    if(!_bad_members.contains(member_idx)) {
      _bad_members.append(member_idx);
    }
  }

  void TolerantTreeRound::AddBadMembers(const QVector<int> &more) {
    for(int i=0; i<more.count(); i++) {
      const int member_idx = more[i];
      AddBadMember(member_idx);
    }
  }

  void TolerantTreeRound::KeyShuffleFinished()
  {
    if(!_key_shuffle_round->Successful()) {
      AddBadMembers(_key_shuffle_round->GetBadMembers());
      FoundBadMembers();
      return;
    }

    if(_key_shuffle_sink.Count() != GetGroup().Count()) {
      qWarning() << "Did not receive a descriptor from everyone.";
    }

    qDebug() << "Finished key shuffle";
    uint count = static_cast<uint>(_key_shuffle_sink.Count());
    for(uint idx = 0; idx < count; idx++) {
      QPair<QSharedPointer<ISender>, QByteArray> pair(_key_shuffle_sink.At(idx));
      _slot_signing_keys.append(ParseSigningKey(pair.second));
      
      // Header fields in every slot
      _header_lengths.append(1  // shuffle byte
          + 4                   // phase
          + 4                   // message length
          + (_slot_signing_keys.last()->GetKeySize() / 8) // signature
          + _message_randomizer.GetHeaderLength() // randomizer seed
        );

      // Everyone starts out with a zero-length message
      _message_lengths.append(0);

      if(_key_shuffle_data == pair.second) {
        _my_idx = idx;
      }
    }

    PrepForNextPhase();

    SendCommits();
  }

  void TolerantTreeRound::ChangeState(State new_state) 
  {
    _state = new_state;
    uint count = static_cast<uint>(_offline_log.Count());
    for(uint idx = 0; idx < count; idx++) {
      QPair<QByteArray, Id> entry = _offline_log.At(idx);
      ProcessData(entry.second, entry.first);
    }

    _offline_log.Clear();
  }

  bool TolerantTreeRound::ReadyForMessage(MessageType mtype)
  {
    switch(_state) {
      case State_Offline: 
        return false;
      case State_SigningKeyShuffling:
        return false;
      case State_CommitSharing:
        return (mtype == MessageType_UserCommitData) ||
          (mtype == MessageType_ServerCommitData);
      case State_CommitReceiving:
        return (mtype == MessageType_LeaderCommitData);
      case State_DataSharing:
        return (mtype == MessageType_UserBulkData) ||
          (mtype == MessageType_ServerBulkData);
      case State_DataReceiving:
        return (mtype == MessageType_LeaderBulkData);
      case State_Finished:
        qWarning() << "Received message after node finished";
        return false;
      default:
        qFatal("Should never get here");

      return false;
    }
  }

}
}
}
