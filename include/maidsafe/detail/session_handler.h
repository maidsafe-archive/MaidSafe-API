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

#ifndef MAIDSAFE_DETAIL_SESSION_HANDLER_H_
#define MAIDSAFE_DETAIL_SESSION_HANDLER_H_

#include <memory>
#include <string>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/authentication/user_credentials.h"
#include "maidsafe/common/authentication/user_credential_utils.h"
#include "maidsafe/common/data_types/immutable_data.h"
#include "maidsafe/common/data_types/mutable_data.h"
#include "maidsafe/common/data_types/structured_data_versions.h"

#include "maidsafe/nfs/client/maid_node_nfs.h"
#include "maidsafe/detail/session_getter.h"

namespace maidsafe {

namespace detail {

Identity GetSessionLocation(const authentication::UserCredentials::Keyword& keyword,
                            const authentication::UserCredentials::Pin& pin);

// friend of AnonymousSession
// Update session here ?
template <typename AccountType>
ImmutableData EncryptSession(const authentication::UserCredentials& user_credentials,
                             AccountType& account);

template <typename AccountType>
AccountType DecryptSession(const authentication::UserCredentials& user_credentials,
                       const ImmutableData& encrypted_session);


template <typename AccountType>
class SessionHandler {
 public:
  // This constructor should be used before logging in to an existing account, i.e. where the
  // session has not yet been retrieved from the network.  Throws std::exception on error.
  explicit SessionHandler(std::shared_ptr<detail::SessionGetter> session_getter = nullptr);

  // This constructor should be used when creating a new account, i.e. where a session has never
  // been put to the network.  'client' should already be joined to the network.  Internally saves
  // the first session after creating the new account.  Throws std::exception on error.
  SessionHandler(AccountType&& account, std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs,
                 authentication::UserCredentials&& user_credentials);

  // Retrieves and decrypts session info when logging in to an existing account.  Throws
  // std::exception on error.
  void Login(authentication::UserCredentials&& user_credentials);

  // Saves session on the network using 'client', which should already be joined to the network.
  // Throws std::exception on error.
  void Save(std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs);

  AccountType& account();

 private:
  std::unique_ptr<AccountType> account_;
  StructuredDataVersions::VersionName current_session_version_;
  std::shared_ptr<detail::SessionGetter> account_getter_;
  authentication::UserCredentials user_credentials_;
};



//================== Implementation ================================================================

// TODO(Team) : Need to finalise if we are concatenating encrypted passport to encrypted session
// Or encrypt the whole session including encrypted passport
template <typename AccountType>
ImmutableData EncryptSession(const authentication::UserCredentials& user_credentials,
                             AccountType& account) {
  NonEmptyString serialised_session{ account.Serialise(user_credentials).data };
  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  return ImmutableData{ crypto::SymmEncrypt(
      authentication::Obfuscate(user_credentials, serialised_session),
      authentication::DeriveSymmEncryptKey(secure_password),
      authentication::DeriveSymmEncryptIv(secure_password)).data };
}

template <typename AccountType>
AccountType DecryptSession(const authentication::UserCredentials& user_credentials,
                       const ImmutableData& encrypted_session) {
  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  return AccountType{ typename AccountType::SerialisedType{
      authentication::Obfuscate(
          user_credentials,
          crypto::SymmDecrypt(crypto::CipherText{ encrypted_session.data() },
                              authentication::DeriveSymmEncryptKey(secure_password),
                              authentication::DeriveSymmEncryptIv(secure_password))).string() },
      user_credentials };
}

template <typename AccountType>
SessionHandler<AccountType>::SessionHandler(std::shared_ptr<detail::SessionGetter> account_getter)
    : account_(),
      current_session_version_(),
      account_getter_(account_getter ? account_getter :
                                       SessionGetter::CreateSessionGetter().get()),
      user_credentials_() {}

template <typename AccountType>
SessionHandler<AccountType>::SessionHandler(AccountType&& account,
                                        std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs,
                                        authentication::UserCredentials&& user_credentials)
    : account_(maidsafe::make_unique<AccountType>(std::move(account))),
      current_session_version_(),
      account_getter_(),
      user_credentials_(std::move(user_credentials)) {
  // throw if client & session are not coherent
  // TODO(Prakash) Validate credentials
  Identity account_location{ GetSessionLocation(*user_credentials_.keyword,
                                                *user_credentials_.pin) };
  LOG(kVerbose) << "Session location: " << HexSubstr(account_location);
  ImmutableData encrypted_serialised_session{
      EncryptSession(user_credentials_, *account_) };
  LOG(kVerbose) << "Immutable encrypted Session data name: "
                << HexSubstr(encrypted_serialised_session.name()->string());
  try {
    LOG(kVerbose) << "Put encrypted_serialised_session";
    auto put_future = maid_node_nfs->Put(encrypted_serialised_session);
    put_future.get();
    StructuredDataVersions::VersionName session_version(0, encrypted_serialised_session.name());
    auto create_version_tree_future = maid_node_nfs->CreateVersionTree(
        MutableData::Name(account_location), session_version, 20, 1);
    create_version_tree_future.get();
    current_session_version_ = session_version;
    LOG(kVerbose) << "Created Version tree";
  } catch (const std::exception& e) {
    LOG(kError) << "Failed to store session. " << boost::diagnostic_information(e);
    maid_node_nfs->Delete(encrypted_serialised_session.name());
    // TODO(Fraser) BEFORE_RELEASE need to delete version tree here
    throw;
  }
}

template <typename AccountType>
void SessionHandler<AccountType>::Login(authentication::UserCredentials&& user_credentials) {
  if (account_)
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));

  Identity account_location{ GetSessionLocation(*user_credentials.keyword,
                                                *user_credentials.pin) };
  LOG(kVerbose) << "Session location: " << HexSubstr(account_location);
  try {
    auto versions_future =
        account_getter_->data_getter().GetVersions(MutableData::Name(account_location));
    LOG(kVerbose) << "Waiting for versions_future";
    auto versions(versions_future.get());
    LOG(kVerbose) << "GetVersions from session location succeeded";
    assert(versions.size() == 1U);
    // TODO(Fraser#5#): 2014-04-17 - Get more than just the latest version - possibly just for the
    // case where the latest one fails.  Or just throw, but add 'int version_number' to this
    // function's signature where 0 == most recent, 1 == second newest, etc.
    auto encrypted_serialised_account_future(account_getter_->data_getter().Get(versions.at(0).id));
    auto encrypted_serialised_session(encrypted_serialised_account_future.get());
    LOG(kVerbose) << "Get encrypted_serialised_session succeeded";
    account_ = maidsafe::make_unique<AccountType>(
        DecryptSession<AccountType>(user_credentials, encrypted_serialised_session));
    current_session_version_ = versions.at(0);
    user_credentials_ = std::move(user_credentials);
    account_getter_.reset();
  } catch (const std::exception& e) {
    LOG(kError) << "Failed to Login. Error: " << boost::diagnostic_information(e);
    throw;
  }
}

template <typename AccountType>
void SessionHandler<AccountType>::Save(std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs) {
  ImmutableData encrypted_serialised_session(EncryptSession(user_credentials_, *account_));
  LOG(kVerbose) << " Immutable encrypted new Session data name : "
                << HexSubstr(encrypted_serialised_session.name()->string());
  try {
    auto put_future = maid_node_nfs->Put(encrypted_serialised_session);
    put_future.get();
    StructuredDataVersions::VersionName new_session_version{ current_session_version_.index + 1,
                                                             encrypted_serialised_session.name() };
    assert(current_session_version_.id != new_session_version.id);
    Identity account_location{ GetSessionLocation(*user_credentials_.keyword,
                                                  *user_credentials_.pin) };
    LOG(kVerbose) << "Account location: " << HexSubstr(account_location);
    auto put_version_future = maid_node_nfs->PutVersion(MutableData::Name(account_location),
                                                        current_session_version_,
                                                        new_session_version);
    put_version_future.get();
    current_session_version_ = new_session_version;
    LOG(kVerbose) << "Save Session succeeded";
  } catch (const std::exception& e) {
    LOG(kError) << boost::diagnostic_information(e);
    maid_node_nfs->Delete(encrypted_serialised_session.name());
    throw;
  }
}

template <typename AccountType>
AccountType& SessionHandler<AccountType>::account() {
  assert(account_);
  return *account_;
}

}  // namespace detail

}  // namespace maidsafe

#endif  // MAIDSAFE_DETAIL_SESSION_HANDLER_H_
