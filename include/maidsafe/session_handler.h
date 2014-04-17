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

#ifndef MAIDSAFE_SESSION_HANDLER_H_
#define MAIDSAFE_SESSION_HANDLER_H_

#include <string>

#include "maidsafe/client.h"
#include "maidsafe/detail/session_getter.h"
#include "maidsafe/common/authentication/user_credentials.h"
#include "maidsafe/common/authentication/user_credential_utils.h"

namespace maidsafe {

namespace detail {

Identity GetSessionLocation(const authentication::UserCredentials::Keyword& keyword,
                            const authentication::UserCredentials::Pin& pin);

// friend of AnonymousSession
// Update session here ?
template <typename Session>
ImmutableData EncryptSession(const authentication::UserCredentials& user_credentials,
                             Session& session);

template <typename Session>
Session DecryptSession(const authentication::UserCredentials& user_credentials,
                       const ImmutableData& encrypted_session);

}  // namespace detail

template <typename Session>
class SessionHandler {
 public:
  // Used when logging in to existing account
  explicit SessionHandler(const BootstrapInfo& bootstrap_info);
  // Used for creating new account
  // throws if account can't be created on network
  SessionHandler(Session&& session, Client& client,
                 authentication::UserCredentials&& user_credentials);
  // No need to login for new accounts
  void Login(authentication::UserCredentials&& user_credentials);
  // Saves session on the network using client
  void Save(Client& client);

  Session& session();

 private:
  ImmutableData EncryptSession();

  std::unique_ptr<Session> session_;
  StructuredDataVersions::VersionName current_session_version_;
  std::unique_ptr<detail::SessionGetter> session_getter_;
  authentication::UserCredentials user_credentials_;
};



//================== Implementation ================================================================


namespace detail {

// Update session here ?
// TODO(Team) : Need to finalise if we are concatenating encrypted passport to encrypted session
// Or encrypt the whole session including encrypted passport
template <typename Session>
ImmutableData EncryptSession(const authentication::UserCredentials& user_credentials,
                             Session& session) {
  NonEmptyString serialised_session{ session.Serialise(user_credentials).data };

  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  return ImmutableData{ crypto::SymmEncrypt(
      authentication::Obfuscate(user_credentials, serialised_session),
      authentication::DeriveSymmEncryptKey(secure_password),
      authentication::DeriveSymmEncryptIv(secure_password)).data };
}

template <typename Session>
Session DecryptSession(const authentication::UserCredentials& user_credentials,
                       const ImmutableData& encrypted_session) {
  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  return Session{ typename Session::SerialisedType{
      authentication::Obfuscate(
          user_credentials,
          crypto::SymmDecrypt(crypto::CipherText{ encrypted_session.data() },
                              authentication::DeriveSymmEncryptKey(secure_password),
                              authentication::DeriveSymmEncryptIv(secure_password))).string() },
        user_credentials };
}

}  // namespace detail


// Joins with anonymous data getter for getting session data from network
// Used for already existing accounts
template <typename Session>
SessionHandler<Session>::SessionHandler(const BootstrapInfo& bootstrap_info)
    : session_(),
      current_session_version_(),
      session_getter_(new detail::SessionGetter(bootstrap_info)),
      user_credentials_() {}

// Used when creating new account
// expects a joined client as a parameter
// throws if failed to create maid account
// Internally saves session after creating user account
// throws if failed to save session
template <typename Session>
SessionHandler<Session>::SessionHandler(Session&& session, Client& client,
                                        authentication::UserCredentials&& user_credentials)
    : session_(new Session(std::move(session))),
      current_session_version_(),
      session_getter_(),  // Not reqired when creating account.
      user_credentials_(std::move(user_credentials)) {
  // throw if client & session are not coherent
  // TODO(Prakash) Validate credentials
  auto session_location(detail::GetSessionLocation(*user_credentials_.keyword,
                                                   *user_credentials_.pin));
  LOG(kInfo) << "Session location : " << DebugId(NodeId(session_location.string()));
  ImmutableData encrypted_serialised_session(detail::EncryptSession(user_credentials_, *session_));
  LOG(kInfo) << " Immutable encrypted Session data name : "
             << HexSubstr(encrypted_serialised_session.name()->string());
  try {
    LOG(kInfo) << "Put encrypted_serialised_session ";
    auto put_future = client.Put(encrypted_serialised_session);
    // put_future.get();   // FIXME Prakash BEFORE_RELEASE
    StructuredDataVersions::VersionName session_version(0, encrypted_serialised_session.name());
    auto create_version_tree_future = client.CreateVersionTree(
        MutableData::Name(session_location), session_version, 20, 1);
    create_version_tree_future.get();
    current_session_version_ = session_version;
    LOG(kInfo) << "Created Version tree";
  } catch (const std::exception& e) {
    LOG(kError) << "Failed to store session. " << boost::diagnostic_information(e);
    client.Delete(encrypted_serialised_session.name());
    // TODO(Fraser) BEFORE_RELEASE need to delete version tree here
    throw;
  }
}

// throw if session already exists
// this method should not be called when creating account with session handle construct
template <typename Session>
void SessionHandler<Session>::Login(authentication::UserCredentials&& user_credentials) {
  if (session_)
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));

  auto session_location(detail::GetSessionLocation(*user_credentials.keyword,
                                                   *user_credentials.pin));
  LOG(kInfo) << "Session location : " << DebugId(NodeId(session_location.string()));
  auto versions_future =
      session_getter_->data_getter().GetVersions(MutableData::Name(session_location));
  LOG(kInfo) << "waiting on versions_future";
  auto versions(versions_future.get());
  LOG(kInfo) << "GetVersions from session location succeded ";
  assert(versions.size() == 1);
  auto encrypted_serialised_session_future(session_getter_->data_getter().Get(versions.at(0).id));
  auto encrypted_serialised_session(encrypted_serialised_session_future.get());
  LOG(kInfo) << "Get encrypted_serialised_session succeded";
  session_.reset(new Session(detail::DecryptSession<Session>(user_credentials,
                                                             encrypted_serialised_session)));
  current_session_version_ = versions.at(0);
  user_credentials_ = std::move(user_credentials);
  session_getter_.reset();
}

template <typename Session>
void SessionHandler<Session>::Save(Client& client) {
  ImmutableData encrypted_serialised_session(detail::EncryptSession(user_credentials_, *session_));
  LOG(kInfo) << " Immutable encrypted new Session data name : "
             << HexSubstr(encrypted_serialised_session.name()->string());
  try {
    auto put_future = client.Put(encrypted_serialised_session);
//  put_future.get();  // FIXME Prakash BEFORE_RELEASE
    StructuredDataVersions::VersionName new_session_version(current_session_version_.index + 1,
                                                            encrypted_serialised_session.name());
    assert(current_session_version_.id != new_session_version.id);
    auto session_location(detail::GetSessionLocation(*user_credentials_.keyword,
                                                     *user_credentials_.pin));
    LOG(kInfo) << "Session location : " << DebugId(NodeId(session_location.string()));
    auto put_version_future = client.PutVersion(MutableData::Name(session_location),
                                                current_session_version_,
                                                new_session_version);
    put_version_future.get();
    current_session_version_ = new_session_version;
    LOG(kInfo) << "Save Session succeded";
  } catch (const std::exception& e) {
    LOG(kError) << boost::diagnostic_information(e);
    client.Delete(encrypted_serialised_session.name());
    // TODO(Fraser) BEFORE_RELEASE need to delete version tree here
    throw;
  }
}

template <typename Session>
Session& SessionHandler<Session>::session() {
  assert(session_);
  return *session_;
}

}  // namespace maidsafe

#endif  // MAIDSAFE_SESSION_HANDLER_H_
