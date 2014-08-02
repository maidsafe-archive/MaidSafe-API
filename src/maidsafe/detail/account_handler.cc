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

#include "maidsafe/detail/account_handler.h"

#include <utility>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/authentication/user_credential_utils.h"
#include "maidsafe/common/data_types/immutable_data.h"
#include "maidsafe/common/data_types/mutable_data.h"

#include "maidsafe/account_getter.h"

namespace maidsafe {

namespace detail {

Identity GetAccountLocation(const authentication::UserCredentials::Keyword& keyword,
                            const authentication::UserCredentials::Pin& pin) {
  return Identity{ crypto::Hash<crypto::SHA512>(keyword.Hash<crypto::SHA512>().string() +
                                                pin.Hash<crypto::SHA512>().string()) };
}

AccountHandler::AccountHandler() : account_(), current_account_version_(), user_credentials_() {}

AccountHandler::AccountHandler(Account&& account,
                               authentication::UserCredentials&& user_credentials,
                               nfs_client::MaidNodeNfs& maid_node_nfs)
    : account_(std::move(account)),
      current_account_version_(),
      user_credentials_(std::move(user_credentials)) {
  // throw if private_client & account are not coherent
  // TODO(Prakash) Validate credentials
  Identity account_location{ GetAccountLocation(*user_credentials_.keyword,
                                                *user_credentials_.pin) };
  LOG(kVerbose) << "Account location: " << HexSubstr(account_location);
  ImmutableData encrypted_account{ EncryptAccount(user_credentials_, account_) };
  LOG(kVerbose) << "Immutable encrypted Account data name: "
                << HexSubstr(encrypted_account.name()->string());
  try {
    LOG(kVerbose) << "Put encrypted_account";
    auto put_future = maid_node_nfs.Put(encrypted_account);
    put_future.get();
    StructuredDataVersions::VersionName account_version(0, encrypted_account.name());
    auto create_version_tree_future = maid_node_nfs.CreateVersionTree(
        MutableData::Name(account_location), account_version, 20, 1);
    create_version_tree_future.get();
    current_account_version_ = account_version;
    LOG(kVerbose) << "Created Version tree";
  }
  catch (const std::exception& e) {
    LOG(kError) << "Failed to store account: " << boost::diagnostic_information(e);
    maid_node_nfs.Delete(encrypted_account.name());
    // TODO(Fraser) BEFORE_RELEASE need to delete version tree here
    throw;
  }
}

AccountHandler::AccountHandler(AccountHandler&& other) MAIDSAFE_NOEXCEPT
    : account_(std::move(other.account_)),
      current_account_version_(std::move(other.current_account_version_)),
      user_credentials_(std::move(other.user_credentials_)) {}

AccountHandler& AccountHandler::operator=(AccountHandler other) {
  swap(*this, other);
  return *this;
}

void AccountHandler::Login(authentication::UserCredentials&& user_credentials,
                           AccountGetter& account_getter) {
  if (account_.passport)  // already logged in
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));

  Identity account_location{ GetAccountLocation(*user_credentials.keyword,
                                                *user_credentials.pin) };
  LOG(kVerbose) << "Account location: " << HexSubstr(account_location);
  try {
    auto versions_future =
        account_getter.data_getter().GetVersions(MutableData::Name(account_location));
    LOG(kVerbose) << "Waiting for versions_future";
    auto versions(versions_future.get());
    LOG(kVerbose) << "GetVersions from account location succeeded";
    assert(versions.size() == 1U);
    // TODO(Fraser#5#): 2014-04-17 - Get more than just the latest version - possibly just for the
    // case where the latest one fails.  Or just throw, but add 'int version_number' to this
    // function's signature where 0 == most recent, 1 == second newest, etc.
    auto encrypted_account_future(account_getter.data_getter().Get(versions.at(0).id));
    auto encrypted_account(encrypted_account_future.get());
    LOG(kVerbose) << "Get encrypted_account succeeded";
    account_ = Account{ encrypted_account, user_credentials };
    current_account_version_ = versions.at(0);
    user_credentials_ = std::move(user_credentials);
  }
  catch (const std::exception& e) {
    LOG(kError) << "Failed to login: " << boost::diagnostic_information(e);
    throw;
  }
}

void AccountHandler::Save(nfs_client::MaidNodeNfs& maid_node_nfs) {
  // The only member which is modified in this process is the account timestamp.
  on_scope_exit strong_guarantee{ on_scope_exit::RevertValue(account_.timestamp) };

  ImmutableData encrypted_account(EncryptAccount(user_credentials_, account_));
  LOG(kVerbose) << " Immutable encrypted new Account data name: "
                << HexSubstr(encrypted_account.name()->string());
  try {
    auto put_future = maid_node_nfs.Put(encrypted_account);
    put_future.get();
    StructuredDataVersions::VersionName new_account_version{ current_account_version_.index + 1,
                                                             encrypted_account.name() };
    assert(current_account_version_.id != new_account_version.id);
    Identity account_location{ GetAccountLocation(*user_credentials_.keyword,
                                                  *user_credentials_.pin) };
    LOG(kVerbose) << "Account location: " << HexSubstr(account_location);
    auto put_version_future = maid_node_nfs.PutVersion(MutableData::Name(account_location),
                                                       current_account_version_,
                                                       new_account_version);
    put_version_future.get();
    current_account_version_ = new_account_version;
    LOG(kVerbose) << "Save Account succeeded";
    strong_guarantee.Release();
  } catch (const std::exception& e) {
    LOG(kError) << boost::diagnostic_information(e);
    maid_node_nfs.Delete(encrypted_account.name());
    throw;
  }
}

void swap(AccountHandler& lhs, AccountHandler& rhs) MAIDSAFE_NOEXCEPT {
  using std::swap;
  swap(lhs.account_, rhs.account_);
  swap(lhs.current_account_version_, rhs.current_account_version_);
  swap(lhs.user_credentials_, rhs.user_credentials_);
}

}  // namespace detail

}  // namespace maidsafe
