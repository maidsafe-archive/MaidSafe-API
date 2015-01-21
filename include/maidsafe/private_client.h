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

#include <cstdint>
#include <future>
#include <memory>
#include <string>

#include "boost/signals2/signal.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/nfs/client/maid_client.h"

#include "maidsafe/detail/account_handler.h"

namespace maidsafe {

namespace detail{ class AccountGetter; }

class PrivateClient {
 public:
  typedef std::string Keyword;
  typedef uint32_t Pin;
  typedef std::string Password;
  typedef boost::signals2::signal<void(int32_t)> OnNetworkHealthChange;

  // Move-constructible and move-assignable only.
  PrivateClient(PrivateClient&& other) MAIDSAFE_NOEXCEPT;
  PrivateClient& operator=(PrivateClient other);
  friend void swap(PrivateClient& lhs, PrivateClient& rhs) MAIDSAFE_NOEXCEPT;
  PrivateClient(const PrivateClient&) = delete;
#if defined(_MSC_VER) && _MSC_VER == 1800  // VS 2013
  // A bug in MSVC 2013 requires anything returned in a std::future to be default-constructible.
  PrivateClient() : maid_client_(), account_handler_() {}
#endif

  // Retrieves and decrypts account info and logs in to an existing account.  Throws on error.
  static std::future<std::unique_ptr<PrivateClient>> Login(Keyword keyword, Pin pin,
                                                           Password password);

  // This function should be used when creating a new account, i.e. where a account has never
  // been put to the network.  Internally saves the first encrypted account after creating the new
  // account.  Throws on error.
  static std::future<std::unique_ptr<PrivateClient>> CreateAccount(Keyword keyword, Pin pin,
                                                                   Password password);

  // Throws on error, with strong exception guarantee.  After calling, the class should be
  // destructed as it is no longer connected to the network.
  void Logout();

 private:
  // For already existing accounts.
  PrivateClient(Keyword keyword, Pin pin, Password password, detail::AccountGetter& account_getter);

  // For new accounts.  Throws on failure to create account.
  PrivateClient(Keyword keyword, Pin pin, Password password,
                passport::MaidAndSigner&& maid_and_signer);

  std::shared_ptr<nfs_client::MaidClient> maid_client_;
  detail::AccountHandler account_handler_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CLIENT_H_
