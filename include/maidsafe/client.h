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

#ifndef MAIDSAFE_CLIENT_H_
#define MAIDSAFE_CLIENT_H_


#include "boost/signals2/signal.hpp"
#include "boost/thread/future.hpp"

#include "maidsafe/passport/passport.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/routing/bootstrap_file_operations.h"

#include "maidsafe/detail/session_getter.h"
#include "maidsafe/session_handler.h"

namespace maidsafe {

namespace nfs_client { class MaidNodeNfs; }

template <typename Session>
class Client {
 public:
  // FIXME
  typedef std::string Keyword;
  typedef uint32_t Pin;
  typedef std::string Password;

  typedef boost::signals2::signal<void(int32_t)> OnNetworkHealthChange;

  static std::shared_ptr<Client> Login(const Keyword& keyword,
      const Pin& pin, const Password& password,
      std::shared_ptr<detail::SessionGetter> session_getter = nullptr);

  static std::shared_ptr<Client> CreateAccount(const Keyword& keyword,
                                               const Pin& pin,
                                               const Password& password);

  ~Client();

 private:

  // For already existing accounts.
  Client(const Keyword& keyword, const Pin& pin, const Password& password,
         std::shared_ptr<detail::SessionGetter> session_getter);

  // For new accounts.  Throws on failure to create account.
  Client(const Keyword& keyword, const Pin& pin, const Password& password);

  std::unique_ptr<SessionHandler<Session>> session_handler_;
  std::shared_ptr<nfs_client::MaidNodeNfs> maid_node_nfs_;
};


template <typename Session>
std::shared_ptr<Client<Session>> Client<Session>::CreateAccount(const Keyword& keyword,
    const Pin& pin, const Password& password) {
  return std::shared_ptr<Client<Session>>(new Client<Session>(keyword, pin, password));
}


template <typename Session>
std::shared_ptr<Client<Session>> Client<Session>::Login(
    const Keyword& keyword, const Pin& pin, const Password& password,
    std::shared_ptr<detail::SessionGetter> session_getter) {
  return std::shared_ptr<Client<Session>>(new Client<Session>(keyword, pin, password,
                                                              session_getter));
}

// For new accounts.  Throws on failure to create account.
template <typename Session>
Client<Session>::Client(const Keyword& keyword, const Pin& pin, const Password& password)
    : session_handler_(),
      maid_node_nfs_() {
  routing::BootstrapContacts bootstrap_contacts;  // FIXME

  authentication::UserCredentials user_credentials;  // FIXME
  user_credentials.keyword = maidsafe::make_unique<authentication::UserCredentials::Keyword>(
      keyword);
  user_credentials.pin = maidsafe::make_unique<authentication::UserCredentials::Pin>(
      std::to_string(pin));
  user_credentials.password = maidsafe::make_unique<authentication::UserCredentials::Password>(
      password);
  auto maid_and_signer(passport::CreateMaidAndSigner());

  maid_node_nfs_ = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer, bootstrap_contacts);
  session_handler_ = maidsafe::make_unique<SessionHandler<Session>>(Session{ maid_and_signer },
                                                                    maid_node_nfs_,
                                                                    std::move(user_credentials));
}

template <typename Session>
Client<Session>::Client(const Keyword& keyword, const Pin& pin, const Password& password,
                        std::shared_ptr<detail::SessionGetter> /*session_getter*/)
    : session_handler_(),
      maid_node_nfs_() {
  routing::BootstrapContacts bootstrap_contacts;  // FIXME
  authentication::UserCredentials user_credentials;  // FIXME
  user_credentials.keyword = maidsafe::make_unique<authentication::UserCredentials::Keyword>(
      keyword);
  user_credentials.pin = maidsafe::make_unique<authentication::UserCredentials::Pin>(
      std::to_string(pin));
  user_credentials.password = maidsafe::make_unique<authentication::UserCredentials::Password>(
      password);
  session_handler_ = maidsafe::make_unique<SessionHandler<Session>>(bootstrap_contacts /*, session_getter*/); //FIXME
  session_handler_->Login(std::move(user_credentials));
  maid_node_nfs_ = nfs_client::MaidNodeNfs::MakeShared(
      session_handler_->session().passport->GetMaid(), bootstrap_contacts);
}

template <typename Session>
Client<Session>::~Client() {
  maid_node_nfs_->Stop();
}

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_H_
