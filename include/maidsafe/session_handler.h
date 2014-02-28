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

#include "maidsafe/user_credentials.h"
#include "maidsafe/detail/session_getter.h"

namespace maidsafe {

namespace detail {

inline Identity GetSessionLocation(const passport::detail::Keyword& keyword,
                                   const passport::detail::Pin& pin) {
  return Identity(crypto::Hash<crypto::SHA512>(keyword.Hash<crypto::SHA512>().string() +
                                               pin.Hash<crypto::SHA512>().string()));
}

// friend of AnonymousSession
//template <typename Session>
//ImmutableData EncryptSession(const UserCredentials& user_credential,
//                             Session& session) {
//  std::string serialised_session(session_.Serialise().data);
//  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, pin));
//  return EncryptedSession(crypto::SymmEncrypt(XorData(keyword, pin, password, serialised_session),
//                                              SecureKey(secure_password),
//                                              SecureIv(secure_password)));
//}

}  // namspace detail

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
  ImmutableData EncryptSession();
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
SessionHandler<Session>::SessionHandler(const Session& session, Client& client,
                                        UserCredentials&& user_credentials)
    : session_(new Session(session)),
      session_getter_(), // Not reqired when creating account.
      user_credentials_(std::move(user_credentials)) {
  // throw if client & session are not coherent
  // TODO Validate credentials
  auto session_location(detail::GetSessionLocation(*user_credentials_.keyword,
                                                   *user_credentials_.pin));
  ImmutableData serialised_session; // = EncryptSession();
  auto put_future = client.Put(serialised_session);
  put_future.get();
  auto create_version_tree_future = client.CreateVersionTree(
      MutableData::Name(session_location),
      StructuredDataVersions::VersionName(0, serialised_session.name()),
      20,
      1);
  create_version_tree_future.get();
}

// throw if session is already exist
// this method should not be called when creating account with session handle construct
template <typename Session>
void SessionHandler<Session>::Login(UserCredentials&& /*user_credentials*/) {
  // throw (session_ !- nullptr);
//  get session location
//  get tip of tree
//  assert vector size == 1 - this is latest version
//  get immutable data with name as per version name
//  decrypt immutable data
  // destroy session getter if success
}

template <typename Session>
void SessionHandler<Session>::Save(Client& /*client*/) {
//    encrypt session
//    store enc session
//    put version (current version name, new version name)
//    relpace current version name with new one
}

template <typename Session>
ImmutableData EncryptSession() {
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, pin));
  return EncryptedSession(crypto::SymmEncrypt(XorData(keyword, pin, password, serialised_session),
                                              SecureKey(secure_password),
                                              SecureIv(secure_password)));
}







}  // namespace maidsafe

#endif  // MAIDSAFE_SESSION_HANDLER_
