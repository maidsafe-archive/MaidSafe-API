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

#include "maidsafe/anonymous_session.h"

#include <memory>

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/tests/test_utils.h"


namespace maidsafe {

namespace test {

// Tests default constructor, which is intended to be used when creating a new account.
TEST(AnonymousSessionTest, BEH_Create) {
  std::unique_ptr<AnonymousSession> session;
  authentication::UserCredentials user_credentials(GetRandomUserCredentials());
  // construct AnonymousSession
  EXPECT_NO_THROW(session.reset(new AnonymousSession(passport::CreateMaidAndSigner())));

  // Check session contents have been initialised as expected
  EXPECT_NO_THROW(session->passport->Encrypt(user_credentials));
  EXPECT_EQ(boost::posix_time::ptime(boost::date_time::not_a_date_time), session->timestamp);
  EXPECT_TRUE(session->ip.is_unspecified());
  EXPECT_EQ(0, session->port);
  EXPECT_FALSE(session->unique_user_id.IsInitialised());
  EXPECT_FALSE(session->root_parent_id.IsInitialised());
}

// Tests serialising function and parsing constructor.
TEST(AnonymousSessionTest, BEH_SaveAndLogin) {
  AnonymousSession session0(passport::CreateMaidAndSigner());
  AnonymousSession::SerialisedType serialised_session0;
  authentication::UserCredentials user_credentials(GetRandomUserCredentials());

  // Check we can handle serialising a default-contructed session.
  EXPECT_NO_THROW(serialised_session0 = session0.Serialise(user_credentials));
  EXPECT_NE(boost::posix_time::ptime(boost::date_time::not_a_date_time), session0.timestamp);

  // Parse default-constructed session and update it.
  std::unique_ptr<AnonymousSession> session1;
  EXPECT_NO_THROW(session1.reset(new AnonymousSession(serialised_session0, user_credentials)));
  EXPECT_EQ(session0.passport->Encrypt(user_credentials),
            session1->passport->Encrypt(user_credentials));
  EXPECT_EQ(session0.timestamp, session1->timestamp);
  EXPECT_EQ(session0.ip, session1->ip);
  EXPECT_EQ(session0.port, session1->port);
  EXPECT_EQ(session0.unique_user_id, session1->unique_user_id);
  EXPECT_EQ(session0.root_parent_id, session1->root_parent_id);

  const boost::asio::ip::address ip(boost::asio::ip::address::from_string("123.124.125.126"));
  const uint16_t port(static_cast<uint16_t>(RandomUint32()));
  const Identity unique_user_id(RandomString(64));
  const Identity root_parent_id(RandomString(64));
  session1->ip = ip;
  session1->port = port;
  session1->unique_user_id = unique_user_id;
  session1->root_parent_id = root_parent_id;

  // Serialise updated session, then parse and check.
  AnonymousSession::SerialisedType serialised_session1;
  EXPECT_NO_THROW(serialised_session1 = session1->Serialise(user_credentials));
  EXPECT_LT(session0.timestamp, session1->timestamp);
  EXPECT_EQ(session1->ip, ip);
  EXPECT_EQ(session1->port, port);
  EXPECT_EQ(session1->unique_user_id, unique_user_id);
  EXPECT_EQ(session1->root_parent_id, root_parent_id);

  std::unique_ptr<AnonymousSession> session2;
  EXPECT_NO_THROW(session2.reset(new AnonymousSession(serialised_session1, user_credentials)));
  EXPECT_EQ(session1->passport->Encrypt(user_credentials),
            session2->passport->Encrypt(user_credentials));
  EXPECT_EQ(session1->timestamp, session2->timestamp);
  EXPECT_EQ(session1->ip, session2->ip);
  EXPECT_EQ(session1->port, session2->port);
  EXPECT_EQ(session1->unique_user_id, session2->unique_user_id);
  EXPECT_EQ(session1->root_parent_id, session2->root_parent_id);
}

TEST(AnonymousSessionTest, BEH_MoveConstructAndAssign) {
  AnonymousSession initial_session(passport::CreateMaidAndSigner());
  authentication::UserCredentials user_credentials(GetRandomUserCredentials());
  initial_session.Serialise(user_credentials);  // to set timestamp
  const crypto::CipherText encrypted_passport(initial_session.passport->Encrypt(user_credentials));
  const boost::posix_time::ptime timestamp(initial_session.timestamp);
  const boost::asio::ip::address ip(boost::asio::ip::address::from_string("234.235.236.237"));
  const uint16_t port(static_cast<uint16_t>(RandomUint32()));
  const Identity unique_user_id(RandomString(64));
  const Identity root_parent_id(RandomString(64));
  initial_session.ip = ip;
  initial_session.port = port;
  initial_session.unique_user_id = unique_user_id;
  initial_session.root_parent_id = root_parent_id;

  AnonymousSession moved_to_session(std::move(initial_session));
  EXPECT_EQ(encrypted_passport, moved_to_session.passport->Encrypt(user_credentials));
  EXPECT_EQ(timestamp, moved_to_session.timestamp);
  EXPECT_EQ(ip, moved_to_session.ip);
  EXPECT_EQ(port, moved_to_session.port);
  EXPECT_EQ(unique_user_id, moved_to_session.unique_user_id);
  EXPECT_EQ(root_parent_id, moved_to_session.root_parent_id);

  AnonymousSession assigned_to_session(passport::CreateMaidAndSigner());
  assigned_to_session = std::move(moved_to_session);
  EXPECT_EQ(encrypted_passport, assigned_to_session.passport->Encrypt(user_credentials));
  EXPECT_EQ(timestamp, assigned_to_session.timestamp);
  EXPECT_EQ(ip, assigned_to_session.ip);
  EXPECT_EQ(port, assigned_to_session.port);
  EXPECT_EQ(unique_user_id, assigned_to_session.unique_user_id);
  EXPECT_EQ(root_parent_id, assigned_to_session.root_parent_id);
}

}  // namespace test

}  // namespace maidsafe
