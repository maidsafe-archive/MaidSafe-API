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

#include "maidsafe/client.h"

#ifdef MAIDSAFE_BSD
extern "C" char **environ;
#endif

#include "maidsafe/common/test.h"
#include "maidsafe/routing/parameters.h"

#include "maidsafe/anonymous_session.h"
#include "maidsafe/detail/session_getter.h"
#include "maidsafe/tests/test_utils.h"


namespace maidsafe {

namespace test {

// Pre-condition : Need a Vault network running
TEST(ClientTest, FUNC_CreateAccount) {
  routing::Parameters::append_local_live_port_endpoint = true;
  auto user_credentials_tuple = GetRandomUserCredentialsTuple();
  auto client = Client<AnonymousSession>::CreateAccount(std::get<0>(user_credentials_tuple),
                                                        std::get<1>(user_credentials_tuple),
                                                        std::get<2>(user_credentials_tuple));
}

TEST(ClientTest, FUNC_CreateAccountMultiple) {
  const int kCount(10);
  routing::Parameters::append_local_live_port_endpoint = true;
  for (int i(0); i != kCount; ++i) {
    auto user_credentials_tuple = GetRandomUserCredentialsTuple();
    auto client = Client<AnonymousSession>::CreateAccount(std::get<0>(user_credentials_tuple),
                                                          std::get<1>(user_credentials_tuple),
                                                          std::get<2>(user_credentials_tuple));
  }
}

TEST(ClientTest, FUNC_Login) {
  routing::Parameters::append_local_live_port_endpoint = true;
  auto user_credentials_tuple = GetRandomUserCredentialsTuple();
  {
    auto client = Client<AnonymousSession>::CreateAccount(std::get<0>(user_credentials_tuple),
                                                          std::get<1>(user_credentials_tuple),
                                                          std::get<2>(user_credentials_tuple));
  }
  auto client = Client<AnonymousSession>::Login(std::get<0>(user_credentials_tuple),
                                                std::get<1>(user_credentials_tuple),
                                                std::get<2>(user_credentials_tuple));
}

TEST(ClientTest, FUNC_LoginWithSessionGetter) {
  routing::Parameters::append_local_live_port_endpoint = true;
  auto user_credentials_tuple = GetRandomUserCredentialsTuple();
  {
    auto client = Client<AnonymousSession>::CreateAccount(std::get<0>(user_credentials_tuple),
                                                          std::get<1>(user_credentials_tuple),
                                                          std::get<2>(user_credentials_tuple));
  }
  auto session_getter_future = maidsafe::detail::SessionGetter::CreateSessionGetter();
  auto client = Client<AnonymousSession>::Login(std::get<0>(user_credentials_tuple),
                                                std::get<1>(user_credentials_tuple),
                                                std::get<2>(user_credentials_tuple),
                                                session_getter_future.get());
}

TEST(ClientTest, FUNC_SaveSession) {
  const int kCount(10);
  routing::Parameters::append_local_live_port_endpoint = true;
  auto user_credentials_tuple = GetRandomUserCredentialsTuple();
  {
    auto client = Client<AnonymousSession>::CreateAccount(std::get<0>(user_credentials_tuple),
                                                          std::get<1>(user_credentials_tuple),
                                                          std::get<2>(user_credentials_tuple));
  }
  auto client = Client<AnonymousSession>::Login(std::get<0>(user_credentials_tuple),
                                                std::get<1>(user_credentials_tuple),
                                                std::get<2>(user_credentials_tuple));
  for (int i(0); i != kCount; ++i) {
    client->SaveSession();
    LOG(kInfo) << "Save session successful !";
  }
}

// TODO  move to nfs
//TEST(ClientTest, FUNC_Constructor) {
//  routing::Parameters::append_local_live_port_endpoint = true;
//  routing::BootstrapContacts bootstrap_contacts;
//  auto maid_and_signer(passport::CreateMaidAndSigner());
//  {
//    auto nfs_new_account =
//        nfs_client::MaidNodeNfs::MakeShared(maid_and_signer, bootstrap_contacts);
//  }
//  LOG(kInfo) << "joining existing account";
//  auto nfs_existing_account = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer.first,
//                                                                  bootstrap_contacts);
//}

//TEST(ClientTest, FUNC_RegisterVault) {
//  routing::Parameters::append_local_live_port_endpoint = true;
//  routing::BootstrapContacts bootstrap_contacts;
//  auto maid_and_signer(passport::CreateMaidAndSigner());
//  {
//    auto nfs_new_account = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer, bootstrap_contacts);
//  }
//  std::cout << "joining existing account" << std::endl;
//  auto nfs_existing_account = nfs_client::MaidNodeNfs::MakeShared(maid_and_signer.first,
//                                                                  bootstrap_contacts);
//  passport::Anpmid anpmid;
//  passport::Pmid pmid(anpmid);
//  passport::PublicPmid public_pmid(pmid);
//  // Put(public_pmid) should be done by VaultManager
//  auto put_future = nfs_existing_account->Put(public_pmid);
//  put_future.get();
//  auto get_future = nfs_existing_account->Get(public_pmid.name());
//  std::cout << " waiting to get pmid public key from network " << std::endl;
//  get_future.get();
//  std::cout << " RegisterVault " << std::endl;
//  auto register_vault_future = nfs_existing_account->RegisterPmid(pmid);
//  register_vault_future.get();
//}

}  // namespace test

}  // namespace maidsafe
