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

#include "maidsafe/private_client.h"

#include <utility>

#include "boost/filesystem.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/detail/account_getter.h"

namespace maidsafe {

namespace {

authentication::UserCredentials ConvertToCredentials(PrivateClient::Keyword keyword,
                                                     PrivateClient::Pin pin,
                                                     PrivateClient::Password password) {
  authentication::UserCredentials user_credentials;
  user_credentials.keyword =
      maidsafe::make_unique<authentication::UserCredentials::Keyword>(keyword);
  user_credentials.pin =
      maidsafe::make_unique<authentication::UserCredentials::Pin>(std::to_string(pin));
  user_credentials.password =
      maidsafe::make_unique<authentication::UserCredentials::Password>(password);
  return user_credentials;
}

}  // unamed namespace

PrivateClient::PrivateClient(PrivateClient&& other) MAIDSAFE_NOEXCEPT
    : maid_node_nfs_(std::move(other.maid_node_nfs_)),
      account_handler_(std::move(other.account_handler_)),
      drive_launcher_(std::move(other.drive_launcher_)) {}

PrivateClient& PrivateClient::operator=(PrivateClient other) {
  swap(*this, other);
  return *this;
}

PrivateClient::PrivateClient(Keyword keyword, Pin pin, Password password,
                             detail::AccountGetter& account_getter)
    : maid_node_nfs_(), account_handler_(), drive_launcher_() {
  account_handler_.Login(ConvertToCredentials(keyword, pin, password), account_getter);
  maid_node_nfs_ =
      nfs_client::MaidNodeNfs::MakeShared(account_handler_.account().passport->GetMaid());
}

PrivateClient::PrivateClient(Keyword keyword, Pin pin, Password password,
                             passport::MaidAndSigner&& maid_and_signer)
    : maid_node_nfs_(nfs_client::MaidNodeNfs::MakeShared(maid_and_signer)),
      account_handler_(detail::Account{ maid_and_signer },
                       ConvertToCredentials(keyword, pin, password), *maid_node_nfs_),
      drive_launcher_() {}

std::future<std::unique_ptr<PrivateClient>> PrivateClient::Login(Keyword keyword, Pin pin,
                                                                 Password password) {
  return std::async(std::launch::async, [=] {
      std::unique_ptr<detail::AccountGetter> account_getter{
          detail::AccountGetter::CreateAccountGetter().get() };
      return std::move(std::unique_ptr<PrivateClient>{
          new PrivateClient{ keyword, pin, password, *account_getter } });
  });
}

std::future<std::unique_ptr<PrivateClient>> PrivateClient::CreateAccount(Keyword keyword, Pin pin,
                                                                         Password password) {
  return std::async(std::launch::async, [=] {
      return std::move(std::unique_ptr<PrivateClient>{
          new PrivateClient{ keyword, pin, password, passport::CreateMaidAndSigner() } });
  });
}

void PrivateClient::Logout() {
  account_handler_.Save(*maid_node_nfs_);
  maid_node_nfs_->Stop();
}

void PrivateClient::Mount(const boost::filesystem::path& drive_name,
                          const boost::filesystem::path& mount_path) {
  crypto::AES256Key symm_key{ RandomString(crypto::AES256_KeySize) };
  crypto::AES256InitialisationVector symm_iv{ RandomString(crypto::AES256_IVSize) };
  crypto::CipherText encrypted_maid(passport::EncryptMaid(
      account_handler_.account().passport->GetMaid(), symm_key, symm_iv));

  drive::Options options;
#ifdef MAIDSAFE_WIN32
  options.mount_path = drive::GetNextAvailableDrivePath();
#else
  options.mount_path = mount_path;
#endif
  options.drive_name = drive_name;
  options.unique_id = account_handler_.account().unique_user_id;
  options.root_parent_id = account_handler_.account().root_parent_id;
  options.encrypted_maid = encrypted_maid->string();
  options.symm_key = symm_key.string();
  options.symm_iv = symm_iv.string();
  drive_launcher_.reset(new drive::Launcher(options));
}

void swap(PrivateClient& lhs, PrivateClient& rhs) MAIDSAFE_NOEXCEPT{
  using std::swap;
  swap(lhs.maid_node_nfs_, rhs.maid_node_nfs_);
  swap(lhs.account_handler_, rhs.account_handler_);
  swap(lhs.drive_launcher_, rhs.drive_launcher_);
}

}  // namespace maidsafe
