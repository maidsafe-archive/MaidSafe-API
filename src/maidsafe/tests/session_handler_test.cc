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

#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/test.h"

#include "maidsafe/routing/parameters.h"

#include "maidsafe/anonymous_session.h"
#include "maidsafe/common/authentication/user_credentials.h"
#include "maidsafe/tests/test_utils.h"

namespace maidsafe {

namespace test {


struct TestSession {
  typedef TaggedValue<std::string, struct AnonymousSessiontag> SerialisedType;
  SerialisedType Serialise(const authentication::UserCredentials&) {
    return SerialisedType(session_string);
  }

  TestSession() : session_string(RandomString(
                                     (RandomInt32() % routing::Parameters::max_data_size) + 1U)) {}
  explicit TestSession(SerialisedType serialised_session, const authentication::UserCredentials&)
      : session_string(serialised_session.data) {}

  std::string session_string;
};

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
    authentication::UserCredentials user_credentials(GetRandomUserCredentials());
    SessionHandler<AnonymousSession> session_handler(std::move(session), client,
                                                     std::move(user_credentials));
  }
}

TEST(SessionHandlerTest, BEH_EncryptDecrypt) {
  for (int i (0); i < 20; ++i) {
    TestSession session;
    authentication::UserCredentials user_credentials(GetRandomUserCredentials());
    ImmutableData encrypted_session = maidsafe::detail::EncryptSession(user_credentials, session);
    TestSession decrypted_session =
        maidsafe::detail::DecryptSession<TestSession>(user_credentials, encrypted_session);
    EXPECT_TRUE(decrypted_session.session_string == session.session_string);
  }
}

TEST(SessionHandlerTest, BEH_EncryptDecryptAnonymousSession) {
  for (int i (0); i < 20; ++i) {
    AnonymousSession session;
    authentication::UserCredentials user_credentials(GetRandomUserCredentials());
    ImmutableData encrypted_session = maidsafe::detail::EncryptSession(user_credentials, session);
    AnonymousSession decrypted_session =
        maidsafe::detail::DecryptSession<AnonymousSession>(user_credentials, encrypted_session);
    // TODO(Prkash) Check passport keys

    EXPECT_TRUE(decrypted_session.passport->GetMaid().name() == session.passport->GetMaid().name());
    EXPECT_TRUE(decrypted_session.timestamp == session.timestamp);
    EXPECT_TRUE(decrypted_session.ip == session.ip);
    EXPECT_TRUE(decrypted_session.port == session.port);
    EXPECT_TRUE(decrypted_session.unique_user_id == session.unique_user_id);
    EXPECT_TRUE(decrypted_session.root_parent_id == session.root_parent_id);
  }
}

TEST(SessionHandlerTest, BEH_Login) {
  routing::Parameters::append_local_live_port_endpoint = true;
  BootstrapInfo bootstrap_info;
  auto user_credentials_tuple(GetRandomUserCredentialsTuple());
  LOG(kInfo) << "Creating new account";
  {
    passport::Anmaid anmaid;
    passport::Maid maid(anmaid);
    Client client(maid, anmaid, bootstrap_info);
    AnonymousSession session;
    authentication::UserCredentials user_credentials(MakeUserCredentials(user_credentials_tuple));
    SessionHandler<AnonymousSession> session_handler(std::move(session), client,
                                                     std::move(user_credentials));
  }
  LOG(kInfo) << "\n\n\n\n\n\n\n\n\n\n\nSession Handler Login for existing account";

  try {
    SessionHandler<AnonymousSession> session_handler(bootstrap_info);
    Sleep(std::chrono::seconds(12));
    LOG(kInfo) << "\n\n\n\n\n\n\n\n\n\n\n About to Login";
    authentication::UserCredentials user_credentials(MakeUserCredentials(user_credentials_tuple));
    session_handler.Login(std::move(user_credentials));
  } catch (std::exception& e) {
    LOG(kError) << "Error on Login :" << boost::diagnostic_information(e);
  }
}

}  // namespace test

}  // namespace maidsafe
