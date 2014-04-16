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

#ifndef MAIDSAFE_ANONYMOUS_SESSION_H_
#define MAIDSAFE_ANONYMOUS_SESSION_H_

#include <cstdint>
#include <memory>
#include <string>

#include "boost/asio/ip/address.hpp"
#include "boost/date_time/posix_time/ptime.hpp"

#include "maidsafe/common/authentication/user_credentials.h"
#include "maidsafe/common/config.h"
#include "maidsafe/common/tagged_value.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/session_handler.h"

namespace maidsafe {

namespace authentication { struct UserCredentials; }

namespace test {

class AnonymousSessionTest_BEH_SaveAndLogin_Test;
class AnonymousSessionTest_BEH_MoveConstructAndAssign_Test;

}  // namespace test

struct AnonymousSession {
  // Type-safety helper to avoid trying to parse a different serialised object as AnonymousSession.
  typedef TaggedValue<std::string, struct AnonymousSessiontag> SerialisedType;

  // Used when creating a new user account.  Creates a new default-constructed passport.  Throws on
  // error.
  explicit AnonymousSession(const passport::MaidAndSigner& maid_and_signer);

  // Move-constructible and move-assignable only
  AnonymousSession(AnonymousSession&& other);
  AnonymousSession& operator=(AnonymousSession other);

  std::unique_ptr<passport::Passport> passport;
  boost::posix_time::ptime timestamp;
  boost::asio::ip::address ip;
  uint16_t port;
  // Optional elements - used by Drive if available.
  Identity unique_user_id, root_parent_id;
  template <typename Session>
  friend ImmutableData detail::EncryptSession(
      const authentication::UserCredentials& user_credentials, Session& session);
  template <typename Session>
  friend Session detail::DecryptSession(const authentication::UserCredentials& user_credentials,
                                        const ImmutableData& encrypted_session);
  friend class test::AnonymousSessionTest_BEH_SaveAndLogin_Test;
  friend class test::AnonymousSessionTest_BEH_MoveConstructAndAssign_Test;

 private:
  AnonymousSession(const AnonymousSession&) = delete;

  // Used when saving session.  Updates 'timestamp' and returns serialised representation of this
  // struct.  Throws on error.
  SerialisedType Serialise(const authentication::UserCredentials& user_credentials);

  // Used when logging in.  Parses session from previously-serialised session.  Throws on error.
  explicit AnonymousSession(SerialisedType serialised_session,
                            const authentication::UserCredentials &user_credentials);
};

void swap(AnonymousSession& lhs, AnonymousSession& rhs) MAIDSAFE_NOEXCEPT;

}  // namespace maidsafe

#endif  // MAIDSAFE_ANONYMOUS_SESSION_H_
