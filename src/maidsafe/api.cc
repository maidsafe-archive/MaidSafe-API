/*  Copyright 2015 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/api.h"

#include <cassert>
#include <condition_variable>
#include <mutex>

#include "asio/io_service_strand.hpp"
#include "cereal/types/set.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/serialisation/serialisation.h"
#include "maidsafe/common/tcp/connection.h"

#include "maidsafe/directory_info.h"

namespace maidsafe {

namespace {

struct ReplyHandler {
  void OnMessage(SerialisedData message) {
    assert(!reply_received);
    try {
      std::lock_guard<std::mutex> lock{mutex};
      reply_received = true;
      directories = Parse<std::set<DirectoryInfo>>(std::move(message));
    } catch (const std::exception& e) {
      LOG(kError) << boost::diagnostic_information(e);
      std::lock_guard<std::mutex> lock{mutex};
      directories.clear();
    }
    cond_var.notify_one();
  }

  void OnConnectionClosed() {
    {
      std::lock_guard<std::mutex> lock{mutex};
      if (reply_received)
        return;
      assert(directories.empty());
    }
    cond_var.notify_one();
  }

  std::set<DirectoryInfo> directories;
  std::mutex mutex;
  std::condition_variable cond_var;
  bool reply_received{false};
};

}  // unnamed namespace

std::set<DirectoryInfo> RegisterAppSession(asymm::PublicKey public_key, tcp::Port port) {
  ReplyHandler reply_handler;
  try {
    AsioService asio_service{1};
    asio::io_service::strand strand{asio_service.service()};
    tcp::ConnectionPtr tcp_connection{tcp::Connection::MakeShared(strand, port)};
    tcp_connection->Start(
        [&](SerialisedData message) { reply_handler.OnMessage(std::move(message)); },
        [&] { reply_handler.OnConnectionClosed(); });
    tcp_connection->Send(Serialise(std::move(public_key)));
    {
      std::unique_lock<std::mutex> lock{reply_handler.mutex};
      reply_handler.cond_var.wait(lock, [&] { return reply_handler.reply_received; });
    }
    if (reply_handler.directories.empty())
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::uninitialised));
  } catch (const std::exception& e) {
    LOG(kError) << boost::diagnostic_information(e);
    throw;
  }
  return reply_handler.directories;
}

asymm::Keys GenerateKeyPair() { return asymm::GenerateKeyPair(); }

}  // namespace maidsafe
