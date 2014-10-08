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
      account_handler_(std::move(other.account_handler_)) {}

PrivateClient& PrivateClient::operator=(PrivateClient other) {
  swap(*this, other);
  return *this;
}

PrivateClient::PrivateClient(Keyword keyword, Pin pin, Password password,
                             detail::AccountGetter& account_getter)
    : maid_node_nfs_(), account_handler_() {
  account_handler_.Login(ConvertToCredentials(keyword, pin, password), account_getter);
  maid_node_nfs_ =
      nfs_client::MaidNodeNfs::MakeShared(account_handler_.account().passport->GetMaid());
}

PrivateClient::PrivateClient(Keyword keyword, Pin pin, Password password,
                             passport::MaidAndSigner&& maid_and_signer)
    : maid_node_nfs_(nfs_client::MaidNodeNfs::MakeShared(maid_and_signer)),
      account_handler_(detail::Account{ maid_and_signer },
                       ConvertToCredentials(keyword, pin, password), *maid_node_nfs_) {}

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
    std::unique_ptr<PrivateClient> ptr;
    try {
      ptr.reset(new PrivateClient{ keyword, pin, password, passport::CreateMaidAndSigner() });
    } catch (...) {
      throw;
    }
    return std::move(ptr);
  });
}

void PrivateClient::Logout() {
  account_handler_.Save(*maid_node_nfs_);
  maid_node_nfs_->Stop();
}

void swap(PrivateClient& lhs, PrivateClient& rhs) MAIDSAFE_NOEXCEPT{
  using std::swap;
  swap(lhs.maid_node_nfs_, rhs.maid_node_nfs_);
  swap(lhs.account_handler_, rhs.account_handler_);
}

}  // namespace maidsafe
