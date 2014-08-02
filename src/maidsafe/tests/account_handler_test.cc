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

#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/test.h"

#include "maidsafe/routing/parameters.h"

#include "maidsafe/account.h"
#include "maidsafe/common/authentication/user_credentials.h"
#include "maidsafe/tests/test_utils.h"

namespace maidsafe {

namespace detail {

namespace test {

struct TestAccount {
  typedef TaggedValue<std::string, struct Accounttag> SerialisedType;
  SerialisedType Serialise(const authentication::UserCredentials&) {
    return SerialisedType(account_string);
  }

  TestAccount() : account_string(RandomString(
                                     (RandomInt32() % routing::Parameters::max_data_size) + 1U)) {}
  explicit TestAccount(SerialisedType serialised_account, const authentication::UserCredentials&)
      : account_string(serialised_account.data) {}

  std::string account_string;
};

TEST(AccountHandlerTest, FUNC_Constructor) {
  routing::Parameters::append_local_live_port_endpoint = true;
  LOG(kInfo) << "Account Handler for exisiting account";
  {
     AccountHandler<Account> account_handler{};
  }

  LOG(kInfo) << "Account Handler for new account";
  {
    auto maid_and_signer(passport::CreateMaidAndSigner());
    auto maid_node_nfs = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer);
    Account account(maid_and_signer);
    authentication::UserCredentials user_credentials(GetRandomUserCredentials());
    AccountHandler<Account> account_handler(std::move(account), maid_node_nfs,
                                                     std::move(user_credentials));
  }
}

TEST(AccountHandlerTest, BEH_EncryptDecrypt) {
  for (int i (0); i < 20; ++i) {
    TestAccount account;
    authentication::UserCredentials user_credentials(GetRandomUserCredentials());
    ImmutableData encrypted_account = maidsafe::detail::EncryptAccount(user_credentials, account);
    TestAccount decrypted_account =
        maidsafe::detail::DecryptAccount<TestAccount>(user_credentials, encrypted_account);
    EXPECT_TRUE(decrypted_account.account_string == account.account_string);
  }
}

TEST(AccountHandlerTest, BEH_EncryptDecryptAccount) {
  for (int i (0); i < 20; ++i) {
    Account account(passport::CreateMaidAndSigner());
    authentication::UserCredentials user_credentials(GetRandomUserCredentials());
    ImmutableData encrypted_account = maidsafe::detail::EncryptAccount(user_credentials, account);
    Account decrypted_account =
        maidsafe::detail::DecryptAccount<Account>(user_credentials, encrypted_account);
    // TODO(Prkash) Check passport keys

    EXPECT_TRUE(decrypted_account.passport->GetMaid().name() == account.passport->GetMaid().name());
    EXPECT_TRUE(decrypted_account.timestamp == account.timestamp);
    EXPECT_TRUE(decrypted_account.ip == account.ip);
    EXPECT_TRUE(decrypted_account.port == account.port);
    EXPECT_TRUE(decrypted_account.unique_user_id == account.unique_user_id);
    EXPECT_TRUE(decrypted_account.root_parent_id == account.root_parent_id);
  }
}

TEST(AccountHandlerTest, FUNC_Login) {
  routing::Parameters::append_local_live_port_endpoint = true;
  auto user_credentials_tuple(GetRandomUserCredentialsTuple());
  auto maid_and_signer(passport::CreateMaidAndSigner());
  {
    LOG(kInfo) << "AccountHandlerTest  -- Creating new account --";
    auto maid_node_nfs = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer);
    Account account(maid_and_signer);
    authentication::UserCredentials user_credentials(MakeUserCredentials(user_credentials_tuple));
    AccountHandler<Account> account_handler(std::move(account), maid_node_nfs,
                                                     std::move(user_credentials));
  }
  try {
    LOG(kInfo) << "AccountHandlerTest  -- Login for existing account --";
    AccountHandler<Account> account_handler{};
    LOG(kInfo) << "About to Login .. ";
    authentication::UserCredentials user_credentials(MakeUserCredentials(user_credentials_tuple));
    account_handler.Login(std::move(user_credentials));
    LOG(kInfo) << "Login successful !";
    ASSERT_TRUE(maid_and_signer.first.name() ==
                account_handler.account().passport->GetMaid().name());
    auto maid_node_nfs =
        nfs_client::MaidNodeNfs::MakeShared(account_handler.account().passport->GetMaid());
    LOG(kInfo) << "PrivateClient connection to account successful !";
  } catch (std::exception& e) {
    LOG(kError) << "Error on Login :" << boost::diagnostic_information(e);
    ASSERT_TRUE(false);
  }
}

TEST(AccountHandlerTest, FUNC_Save) {
  routing::Parameters::append_local_live_port_endpoint = true;
  auto user_credentials_tuple(GetRandomUserCredentialsTuple());
  auto maid_and_signer(passport::CreateMaidAndSigner());
  {
    LOG(kInfo) << "AccountHandlerTest  -- Creating new account --";
    auto maid_node_nfs = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer);
    Account account(maid_and_signer);
    authentication::UserCredentials user_credentials(MakeUserCredentials(user_credentials_tuple));
    AccountHandler<Account> account_handler(std::move(account), maid_node_nfs,
                                                     std::move(user_credentials));
  }
  try {
    LOG(kInfo) << "AccountHandlerTest  -- Login for existing account --";
    AccountHandler<Account> account_handler{};
    LOG(kInfo) << "About to Login .. ";
    authentication::UserCredentials user_credentials(MakeUserCredentials(user_credentials_tuple));
    account_handler.Login(std::move(user_credentials));
    LOG(kInfo) << "Login successful !";
    ASSERT_TRUE(maid_and_signer.first.name() ==
                account_handler.account().passport->GetMaid().name());
    auto maid_node_nfs =
        nfs_client::MaidNodeNfs::MakeShared(account_handler.account().passport->GetMaid());
    LOG(kInfo) << "PrivateClient connection to account successful !";
    LOG(kInfo) << "AccountHandlerTest  -- Saving Account --";
    for (int i(0); i != 10; ++i) {
      account_handler.Save(maid_node_nfs);
      LOG(kInfo) << "Save account successful !";
    }
  } catch (std::exception& e) {
    LOG(kError) << "Error on Login :" << boost::diagnostic_information(e);
    ASSERT_TRUE(false);
  }
}

}  // namespace test

}  // namespace detail

}  // namespace maidsafe
