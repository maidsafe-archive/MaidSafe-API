/*  Copyright 2014 MaidSafe.net limited

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

#ifndef MAIDSAFE_SESSION_HANDLER_
#define MAIDSAFE_SESSION_HANDLER_

#include "maidsafe/client.h"

namespace maidsafe {

class UserCredentials;  // FIXME
class AnonymousSession;  // FIXME
class SessionGetter; // FIXME
template <typename Session>
class SessionHandler {
 public:

  explicit SessionHandler(const BootstrapInfo& bootstrap_info);
  // Used for creating new account
  // throws if account can't be created on network
  SessionHandler(const Session& session, Client& client);

  void Login(UserCredentials);
  // Saves session on the network using client
  void Save(Client& client);

 private :
  std::unique_ptr<typename Session> session_;
  std::unique_ptr<SessionGetter> session_getter_;
  // versions of session
  UserCredentials user_credentials_;
};



//================== Implementation ================================================================

// Joins with anonymous data getter
template <typename Session>
SessionHandler<Session>::SessionHandler(const BootstrapInfo& /*bootstrap_info*/) {

}

// throws if failed to create maid account
// Save session after creating account
// throws if failed to save session
template <typename Session>
SessionHandler<Session>::SessionHandler(const Session& /*session*/, Client& /*client*/) {
}

// throw if session is already exist
// this method should not be called when creating account with session handle construct
template <typename Session>
void SessionHandler<Session>::Login(const UserCredentials& /*user_credentials*/) {
}

template <typename Session>
void SessionHandler<Session>::Save(Client& /*client*/) {

}


}  // namespace maidsafe

#endif  // MAIDSAFE_SESSION_HANDLER_
