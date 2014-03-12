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

#include "maidsafe/client.h"
#include "maidsafe/user_credentials.h"
#include "maidsafe/detail/session_getter.h"

namespace maidsafe {

namespace detail {

Identity GetSessionLocation(const passport::detail::Keyword& keyword,
                            const passport::detail::Pin& pin);

// friend of AnonymousSession
// Update session here ?
template <typename Session>
ImmutableData EncryptSession(const UserCredentials& user_credential,
                             Session& session);

template <typename Session>
Session DecryptSession(const UserCredentials& user_credential,
                       const ImmutableData& encrypted_session);

// TODO move to utility file
crypto::SecurePassword CreateSecureTmidPassword(const passport::detail::Password& password,
                                                const passport::detail::Pin& pin);

// TODO move to utility file
NonEmptyString XorData(const passport::detail::Keyword& keyword,
                       const passport::detail::Pin& pin,
                       const passport::detail::Password& password,
                       const NonEmptyString& data);
crypto::AES256Key SecureKey(const crypto::SecurePassword& secure_password);
crypto::AES256InitialisationVector SecureIv(const crypto::SecurePassword& secure_password);

}  // namespace detail

template <typename Session>
class SessionHandler {
 public:
  // Used when logging in to existing account
  explicit SessionHandler(const BootstrapInfo& bootstrap_info);
  // Used for creating new account
  // throws if account can't be created on network
  SessionHandler(Session&& session, Client& client, UserCredentials&& user_credentials);
  // No need to login for new accounts
  void Login(UserCredentials&& user_credentials);
  // Saves session on the network using client
  void Save(Client& client);

 private:
  ImmutableData EncryptSession();
  std::unique_ptr<Session> session_;
  std::unique_ptr<detail::SessionGetter> session_getter_;
  // versions of session
  UserCredentials user_credentials_;
};



//================== Implementation ================================================================


namespace detail {

// Update session here ?
template <typename Session>
ImmutableData EncryptSession(const UserCredentials& user_credential,
                             Session& session) {
  auto serialised_session(session.Serialise().data);

  crypto::SecurePassword secure_password(CreateSecureTmidPassword(*user_credential.password,
                                                                  *user_credential.pin));
  return ImmutableData(crypto::SymmEncrypt(XorData(*user_credential.keyword,
                                                   *user_credential.pin,
                                                   *user_credential.password,
                                                   NonEmptyString(serialised_session)),
                                           SecureKey(secure_password),
                                           SecureIv(secure_password)));
}

template <typename Session>
Session DecryptSession(const UserCredentials& user_credential,
                       const ImmutableData& encrypted_session) {
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(*user_credential.password,
                                                                  *user_credential.pin));
  return Session(
      Session::SerialisedType(XorData(
          *user_credential.keyword,
          *user_credential.pin,
          *user_credential.password,
          crypto::SymmDecrypt(encrypted_session.data(), SecureKey(secure_password),
                              SecureIv(secure_password)))));
}

}  // namespace detail


// Joins with anonymous data getter for getting session data from network
// Used for already existing accounts
template <typename Session>
SessionHandler<Session>::SessionHandler(const BootstrapInfo& bootstrap_info)
    : session_(),
      session_getter_(new detail::SessionGetter(bootstrap_info)),
      user_credentials_() {}

// Used when creating new account
// expects a joined client as a parameter
// throws if failed to create maid account
// Internally saves session after creating user account
// throws if failed to save session
template <typename Session>
SessionHandler<Session>::SessionHandler(Session&& session, Client& client,
                                        UserCredentials&& user_credentials)
    : session_(new Session(std::move(session))),
      session_getter_(),  // Not reqired when creating account.
      user_credentials_(std::move(user_credentials)) {
  // throw if client & session are not coherent
  // TODO Validate credentials
  auto session_location(detail::GetSessionLocation(*user_credentials_.keyword,
                                                   *user_credentials_.pin));
  ImmutableData encrypted_serialised_session(detail::EncryptSession(user_credentials_, *session_));

  auto put_future = client.Put(encrypted_serialised_session);
  put_future.get();

  try {
    auto create_version_tree_future = client.CreateVersionTree(
        MutableData::Name(session_location),
        StructuredDataVersions::VersionName(0, encrypted_serialised_session.name()),
        20,
        1);
    create_version_tree_future.get();
  } catch (const std::exception& e) {
    LOG(kError) << e.what();
    client.Delete(encrypted_serialised_session.name());
    throw;
  }
}

// throw if session is already exist
// this method should not be called when creating account with session handle construct
template <typename Session>
void SessionHandler<Session>::Login(UserCredentials&& user_credentials) {
  if (session_ != nullptr) {
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
//  get session location
//  get tip of tree
//  assert vector size == 1 - this is latest version
//  get immutable data with name as per version name
//  decrypt immutable data
// destroy session getter if success
  auto session_location(detail::GetSessionLocation(*user_credentials.keyword,
                                                   *user_credentials.pin));
  auto versions_future =
      session_getter_->data_getter().GetVersions(MutableData::Name(session_location));
  auto versions(versions_future.get());
  assert(versions.size() == 1);
  auto encrypted_serialised_session_future(session_getter_->data_getter().Get(versions.at(0).id));
  auto encrypted_serialised_session(encrypted_serialised_session_future.get());
  session_.reset(new Session(detail::DecryptSession<Session>(user_credentials,
                                                             encrypted_serialised_session)));
  user_credentials_ = std::move(user_credentials);
  session_getter_.reset();
}

template <typename Session>
void SessionHandler<Session>::Save(Client& client) {
//    encrypt session
//    store enc session
//    put version (current version name, new version name)
//    relpace current version name with new one
  ImmutableData encrypted_serialised_session(detail::EncryptSession(user_credentials_, *session_));
  auto put_future = client.Put(encrypted_serialised_session);
  put_future.get();

  try {
    auto session_location(detail::GetSessionLocation(*user_credentials_.keyword,
                                                     *user_credentials_.pin));
//    auto put_version_future = client.PutVersion();  // FIXME
//    put_version_future.get();
  } catch (const std::exception& e) {
    LOG(kError) << e.what();
    client.Delete(encrypted_serialised_session.name());
    throw;
  }
}

}  // namespace maidsafe

#endif  // MAIDSAFE_SESSION_HANDLER_H_
