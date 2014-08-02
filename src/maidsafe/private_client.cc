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

#ifndef MAIDSAFE_PRIVATE_CLIENT_H_
#define MAIDSAFE_PRIVATE_CLIENT_H_

#include <string>

#include "boost/signals2/signal.hpp"

#include "maidsafe/passport/passport.h"
#include "maidsafe/passport/types.h"
#include "maidsafe/nfs/private_client/maid_node_nfs.h"

#include "maidsafe/detail/account_getter.h"
#include "maidsafe/detail/account_handler.h"

namespace maidsafe {

class PrivateClient {
 public:
  typedef std::string Keyword;
  typedef uint32_t Pin;
  typedef std::string Password;

  typedef boost::signals2::signal<void(int32_t)> OnNetworkHealthChange;

  PrivateClient(const PrivateClient&) = delete;
  PrivateClient(PrivateClient&&) = delete;
  PrivateClient& operator=(const PrivateClient&) = delete;
  PrivateClient& operator=(PrivateClient&&) = delete;

  // This function should be used when creating a new account, i.e. where a account has never
  // been put to the network. Internally saves the first encrypted account after creating the new
  // account. Throws std::exception on error.
  static std::shared_ptr<PrivateClient> CreateAccount(const Keyword& keyword,
                                               const Pin& pin,
                                               const Password& password);
  // Retrieves and decrypts account info and logs in to an existing account.
  // Throws std::exception on error.
  static std::shared_ptr<PrivateClient> Login(const Keyword& keyword,
      const Pin& pin, const Password& password,
      std::shared_ptr<detail::AccountGetter> account_getter = nullptr);

  // strong exception guarantee
  void SaveAccount();

  ~PrivateClient();

 private:
  // For already existing accounts.
  PrivateClient(const Keyword& keyword, const Pin& pin, const Password& password,
         std::shared_ptr<detail::AccountGetter> account_getter);

  // For new accounts.  Throws on failure to create account.
  PrivateClient(const Keyword& keyword, const Pin& pin, const Password& password);

  std::unique_ptr<detail::AccountHandler<Account>> account_handler_;
  std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs_;
};



//================== Implementation ================================================================
template <typename Account>
std::shared_ptr<PrivateClient<Account>> PrivateClient<Account>::CreateAccount(const Keyword& keyword,
    const Pin& pin, const Password& password) {
  return std::shared_ptr<PrivateClient<Account>>(new PrivateClient<Account>(keyword, pin, password));
}


template <typename Account>
std::shared_ptr<PrivateClient<Account>> PrivateClient<Account>::Login(
    const Keyword& keyword, const Pin& pin, const Password& password,
    std::shared_ptr<detail::AccountGetter> account_getter) {
  return std::shared_ptr<PrivateClient<Account>>(new PrivateClient<Account>(keyword, pin, password,
                                                              account_getter));
}

// For new accounts.  Throws on failure to create account.
template <typename Account>
PrivateClient<Account>::PrivateClient(const Keyword& keyword, const Pin& pin, const Password& password)
    : account_handler_(),
      maid_node_nfs_() {
  authentication::UserCredentials user_credentials;
  user_credentials.keyword = maidsafe::make_unique<authentication::UserCredentials::Keyword>(
      keyword);
  user_credentials.pin = maidsafe::make_unique<authentication::UserCredentials::Pin>(
      std::to_string(pin));
  user_credentials.password = maidsafe::make_unique<authentication::UserCredentials::Password>(
      password);
  auto maid_and_signer(passport::CreateMaidAndSigner());

  maid_node_nfs_ = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer);
  account_handler_ =
      maidsafe::make_unique<detail::AccountHandler<Account>>(Account{ maid_and_signer },
                                                             maid_node_nfs_,
                                                             std::move(user_credentials));
}

template <typename Account>
PrivateClient<Account>::PrivateClient(const Keyword& keyword, const Pin& pin, const Password& password,
                        std::shared_ptr<detail::AccountGetter> account_getter)
    : account_handler_(),
      maid_node_nfs_() {
  authentication::UserCredentials user_credentials;
  user_credentials.keyword = maidsafe::make_unique<authentication::UserCredentials::Keyword>(
      keyword);
  user_credentials.pin = maidsafe::make_unique<authentication::UserCredentials::Pin>(
      std::to_string(pin));
  user_credentials.password = maidsafe::make_unique<authentication::UserCredentials::Password>(
      password);
  account_handler_ = maidsafe::make_unique<detail::AccountHandler<Account>>(account_getter);
  account_handler_->Login(std::move(user_credentials));
  maid_node_nfs_ = nfs_client::MaidNodeNfs::MakeShared(
                     account_handler_->account().passport->GetMaid());
}

template <typename Account>
void PrivateClient<Account>::SaveAccount() {
  account_handler_->Save(maid_node_nfs_);
}

template <typename Account>
PrivateClient<Account>::~PrivateClient() {
  try {
    account_handler_->Save(maid_node_nfs_);
    maid_node_nfs_->Stop();
  } catch (const std::exception& ex) {
    LOG(kError) << "Error while Saving Account. Error : " << boost::diagnostic_information(ex);
  }
}

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CLIENT_H_
