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

#include "maidsafe/session_handler.h"

#include "maidsafe/common/test.h"
#include "maidsafe/routing/parameters.h"

#include "maidsafe/anonymous_session.h"
#include "maidsafe/user_credentials.h"


namespace maidsafe {

namespace test {

UserCredentials GetUserCredentials() {
  UserCredentials user_credentials;
  user_credentials.keyword.reset(new passport::detail::Keyword());
  user_credentials.keyword->Insert(0, 'k');
  user_credentials.keyword->Insert(1, 'e');
  user_credentials.keyword->Insert(2, 'y');
  user_credentials.keyword->Insert(3, 'w');
  user_credentials.keyword->Insert(4, 'o');
  user_credentials.keyword->Insert(5, 'r');
  user_credentials.keyword->Insert(6, 'd');
  user_credentials.keyword->Finalise();

  user_credentials.pin.reset(new passport::detail::Pin());
  user_credentials.pin->Insert(0, '1');
  user_credentials.pin->Insert(1, '2');
  user_credentials.pin->Insert(2, '3');
  user_credentials.pin->Insert(3, '4');
  user_credentials.pin->Finalise();

  user_credentials.password.reset(new passport::detail::Password());
  user_credentials.password->Insert(0, 'p');
  user_credentials.password->Insert(1, 'a');
  user_credentials.password->Insert(2, 's');
  user_credentials.password->Insert(3, 's');
  user_credentials.password->Insert(3, 'w');
  user_credentials.password->Insert(3, 'o');
  user_credentials.password->Insert(3, 'r');
  user_credentials.password->Insert(3, 'd');
  user_credentials.password->Finalise();
  return user_credentials;
}

// Pre-condition : Need a Vault network running
TEST(SessionHandlerTest, BEH_Constructor) {
  routing::Parameters::append_local_live_port_endpoint = true;
  BootstrapInfo bootstrap_info;
  LOG(kInfo) << "Session Handler for exisiting account";
  {
     SessionHandler<AnonymousSession> session_handler(bootstrap_info);
  }

  LOG(kInfo) << "Session Handler for new account";
  {
    passport::Anmaid anmaid;
    passport::Maid maid(anmaid);
    Client client(maid, anmaid, bootstrap_info);
    AnonymousSession session;
    UserCredentials user_credentials(GetUserCredentials());
    SessionHandler<AnonymousSession> session_handler(std::move(session), client,
                                                     std::move(user_credentials));
  }
}


TEST(SessionHandlerTest, BEH_Login) {
  routing::Parameters::append_local_live_port_endpoint = true;
  BootstrapInfo bootstrap_info;
  LOG(kInfo) << "Creating new account";
  {
    passport::Anmaid anmaid;
    passport::Maid maid(anmaid);
    Client client(maid, anmaid, bootstrap_info);
    AnonymousSession session;
    UserCredentials user_credentials(GetUserCredentials());
    SessionHandler<AnonymousSession> session_handler(std::move(session), client,
                                                     std::move(user_credentials));
  }
  LOG(kInfo) << "\n\n\n\n\n\n\n\n\n\n\nSession Handler Login for existing account";

  try {
    SessionHandler<AnonymousSession> session_handler(bootstrap_info);
    Sleep(std::chrono::seconds(12));
    LOG(kInfo) << "\n\n\n\n\n\n\n\n\n\n\n About to Login";
    session_handler.Login(std::move(GetUserCredentials()));
  } catch (std::exception& e) {
    LOG(kError) << "Error on Login :" << boost::diagnostic_information(e);
  }
}

}  // namespace test

}  // namespace maidsafe
