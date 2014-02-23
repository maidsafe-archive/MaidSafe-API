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

#include "maidsafe/detail/session_getter.h"

namespace maidsafe {

class UserCredentials;  // FIXME

template <typename Session>
class SessionHandler {
 public:
  // Used when logging in to existing account
  explicit SessionHandler(const BootstrapInfo& bootstrap_info);
  // Used for creating new account
  // throws if account can't be created on network
  SessionHandler(const Session& session, Client& client, UserCredentials&& user_credentials);
  // No need to login for new accounts
  void Login(UserCredentials&& user_credentials);
  // Saves session on the network using client
  void Save(Client& client);

 private:
  std::unique_ptr<typename Session> session_;
  std::unique_ptr<SessionGetter> session_getter_;
  // versions of session
  UserCredentials user_credentials_;
};



//================== Implementation ================================================================

// Joins with anonymous data getter for getting session data from network
// Used for already existing accounts
template <typename Session>
SessionHandler<Session>::SessionHandler(const BootstrapInfo& bootstrap_info)
    : session_(),
      session_getter_(new SessionGetter(bootstrap_info)),
      user_credentials_() {}

// Used when creating new account
// throws if failed to create maid account
// Internally saves session after creating user account
// throws if failed to save session
template <typename Session>
SessionHandler<Session>::SessionHandler(const Session& session, Client& /*client*/,
                                        UserCredentials&& user_credentials)
    : session_(new Session(session)),
      session_getter_(), // Not reqired when creating account.
      user_credentials_(std::move(user_credentials)) {

}

// throw if session is already exist
// this method should not be called when creating account with session handle construct
template <typename Session>
void SessionHandler<Session>::Login(UserCredentials&& /*user_credentials*/) {
  // throw (session_ !- nullptr);


  // destroy session getter if success
}

template <typename Session>
void SessionHandler<Session>::Save(Client& /*client*/) {

}


}  // namespace maidsafe

#endif  // MAIDSAFE_SESSION_HANDLER_
