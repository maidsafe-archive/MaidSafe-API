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

#ifndef MAIDSAFE_DETAIL_ACCOUNT_HANDLER_H_
#define MAIDSAFE_DETAIL_ACCOUNT_HANDLER_H_

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
#include "maidsafe/detail/account_getter.h"

namespace maidsafe {

namespace detail {

Identity GetAccountLocation(const authentication::UserCredentials::Keyword& keyword,
                            const authentication::UserCredentials::Pin& pin);

// friend of Account
// Update account here ?
ImmutableData EncryptAccount(const authentication::UserCredentials& user_credentials,
                             Account& account);

Account DecryptAccount(const authentication::UserCredentials& user_credentials,
                       const ImmutableData& encrypted_account);


class AccountHandler {
 public:
  AccountHandler(const AccountHandler&) = delete;
  AccountHandler(AccountHandler&&) = delete;
  AccountHandler& operator=(const AccountHandler&) = delete;
  AccountHandler& operator=(AccountHandler&&) = delete;

  // This constructor should be used before logging in to an existing account, i.e. where the
  // account has not yet been retrieved from the network.  Throws std::exception on error.
  explicit AccountHandler(std::shared_ptr<detail::AccountGetter> account_getter = nullptr);

  // This constructor should be used when creating a new account, i.e. where a account has never
  // been put to the network.  'private_client' should already be joined to the network.  Internally saves
  // the first account after creating the new account.  Throws std::exception on error.
  AccountHandler(Account&& account, std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs,
                 authentication::UserCredentials&& user_credentials);

  // Retrieves and decrypts account info when logging in to an existing account.  Throws
  // std::exception on error.
  void Login(authentication::UserCredentials&& user_credentials);

  // Saves account on the network using 'private_client', which should already be joined to the network.
  // Throws std::exception on error.
  void Save(std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs);

  Account& account();

 private:
  std::unique_ptr<Account> account_;
  StructuredDataVersions::VersionName current_account_version_;
  std::shared_ptr<detail::AccountGetter> account_getter_;
  authentication::UserCredentials user_credentials_;
};



//================== Implementation ================================================================

// TODO(Team) : Need to finalise if we are concatenating encrypted passport to encrypted account
// Or encrypt the whole account including encrypted passport
template <typename Account>
ImmutableData EncryptAccount(const authentication::UserCredentials& user_credentials,
                             Account& account) {
  NonEmptyString serialised_account{ account.Serialise(user_credentials).data };
  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  return ImmutableData{ crypto::SymmEncrypt(
      authentication::Obfuscate(user_credentials, serialised_account),
      authentication::DeriveSymmEncryptKey(secure_password),
      authentication::DeriveSymmEncryptIv(secure_password)).data };
}

template <typename Account>
Account DecryptAccount(const authentication::UserCredentials& user_credentials,
                       const ImmutableData& encrypted_account) {
  crypto::SecurePassword secure_password{ authentication::CreateSecurePassword(user_credentials) };
  return Account{ typename Account::SerialisedType{
      authentication::Obfuscate(
          user_credentials,
          crypto::SymmDecrypt(crypto::CipherText{ encrypted_account.data() },
                              authentication::DeriveSymmEncryptKey(secure_password),
                              authentication::DeriveSymmEncryptIv(secure_password))).string() },
      user_credentials };
}

template <typename Account>
AccountHandler<Account>::AccountHandler(std::shared_ptr<detail::AccountGetter> account_getter)
    : account_(),
      current_account_version_(),
      account_getter_(account_getter ? account_getter :
                                       AccountGetter::CreateAccountGetter().get()),
      user_credentials_() {}

template <typename Account>
AccountHandler<Account>::AccountHandler(Account&& account,
                                        std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs,
                                        authentication::UserCredentials&& user_credentials)
    : account_(maidsafe::make_unique<Account>(std::move(account))),
      current_account_version_(),
      account_getter_(),
      user_credentials_(std::move(user_credentials)) {
  // throw if private_client & account are not coherent
  // TODO(Prakash) Validate credentials
  Identity account_location{ GetAccountLocation(*user_credentials_.keyword,
                                                *user_credentials_.pin) };
  LOG(kVerbose) << "Account location: " << HexSubstr(account_location);
  ImmutableData encrypted_serialised_account{
      EncryptAccount(user_credentials_, *account_) };
  LOG(kVerbose) << "Immutable encrypted Account data name: "
                << HexSubstr(encrypted_serialised_account.name()->string());
  try {
    LOG(kVerbose) << "Put encrypted_serialised_account";
    auto put_future = maid_node_nfs->Put(encrypted_serialised_account);
    put_future.get();
    StructuredDataVersions::VersionName account_version(0, encrypted_serialised_account.name());
    auto create_version_tree_future = maid_node_nfs->CreateVersionTree(
        MutableData::Name(account_location), account_version, 20, 1);
    create_version_tree_future.get();
    current_account_version_ = account_version;
    LOG(kVerbose) << "Created Version tree";
  } catch (const std::exception& e) {
    LOG(kError) << "Failed to store account. " << boost::diagnostic_information(e);
    maid_node_nfs->Delete(encrypted_serialised_account.name());
    // TODO(Fraser) BEFORE_RELEASE need to delete version tree here
    throw;
  }
}

template <typename Account>
void AccountHandler<Account>::Login(authentication::UserCredentials&& user_credentials) {
  if (account_)
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));

  Identity account_location{ GetAccountLocation(*user_credentials.keyword,
                                                *user_credentials.pin) };
  LOG(kVerbose) << "Account location: " << HexSubstr(account_location);
  try {
    auto versions_future =
        account_getter_->data_getter().GetVersions(MutableData::Name(account_location));
    LOG(kVerbose) << "Waiting for versions_future";
    auto versions(versions_future.get());
    LOG(kVerbose) << "GetVersions from account location succeeded";
    assert(versions.size() == 1U);
    // TODO(Fraser#5#): 2014-04-17 - Get more than just the latest version - possibly just for the
    // case where the latest one fails.  Or just throw, but add 'int version_number' to this
    // function's signature where 0 == most recent, 1 == second newest, etc.
    auto encrypted_serialised_account_future(account_getter_->data_getter().Get(versions.at(0).id));
    auto encrypted_serialised_account(encrypted_serialised_account_future.get());
    LOG(kVerbose) << "Get encrypted_serialised_account succeeded";
    account_ = maidsafe::make_unique<Account>(
        DecryptAccount<Account>(user_credentials, encrypted_serialised_account));
    current_account_version_ = versions.at(0);
    user_credentials_ = std::move(user_credentials);
    account_getter_.reset();
  } catch (const std::exception& e) {
    LOG(kError) << "Failed to Login. Error: " << boost::diagnostic_information(e);
    throw;
  }
}

template <typename Account>
void AccountHandler<Account>::Save(std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs) {
  ImmutableData encrypted_serialised_account(EncryptAccount(user_credentials_, *account_));
  LOG(kVerbose) << " Immutable encrypted new Account data name : "
                << HexSubstr(encrypted_serialised_account.name()->string());
  try {
    auto put_future = maid_node_nfs->Put(encrypted_serialised_account);
    put_future.get();
    StructuredDataVersions::VersionName new_account_version{ current_account_version_.index + 1,
                                                             encrypted_serialised_account.name() };
    assert(current_account_version_.id != new_account_version.id);
    Identity account_location{ GetAccountLocation(*user_credentials_.keyword,
                                                  *user_credentials_.pin) };
    LOG(kVerbose) << "Account location: " << HexSubstr(account_location);
    auto put_version_future = maid_node_nfs->PutVersion(MutableData::Name(account_location),
                                                        current_account_version_,
                                                        new_account_version);
    put_version_future.get();
    current_account_version_ = new_account_version;
    LOG(kVerbose) << "Save Account succeeded";
  } catch (const std::exception& e) {
    LOG(kError) << boost::diagnostic_information(e);
    maid_node_nfs->Delete(encrypted_serialised_account.name());
    throw;
  }
}

template <typename Account>
Account& AccountHandler<Account>::account() {
  assert(account_);
  return *account_;
}

}  // namespace detail

}  // namespace maidsafe

#endif  // MAIDSAFE_DETAIL_ACCOUNT_HANDLER_H_
