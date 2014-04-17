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

#include "boost/process/child.hpp"
#include "boost/process/execute.hpp"
#include "boost/process/initializers.hpp"
#include "boost/process/wait_for_exit.hpp"

#include "maidsafe/common/process.h"
#include "maidsafe/common/test.h"
#include "maidsafe/routing/parameters.h"

#include "maidsafe/detail/client_impl.h"

namespace maidsafe {

namespace test {

namespace bp = boost::process;

// Pre-condition : Need a Vault network running
TEST(ClientTest, FUNC_Constructor) {
  routing::Parameters::append_local_live_port_endpoint = true;
  BootstrapInfo bootstrap_info;
  auto maid_and_signer(passport::CreateMaidAndSigner());
  {
    Client client_new_account(maid_and_signer, bootstrap_info);
  }
  LOG(kInfo) << "joining existing account";
  Client client_existing_account(maid_and_signer.first, bootstrap_info);
}

TEST(ClientTest, FUNC_RegisterVault) {
  routing::Parameters::append_local_live_port_endpoint = true;
  BootstrapInfo bootstrap_info;
  auto maid_and_signer(passport::CreateMaidAndSigner());
  {
    Client client_new_account(maid_and_signer, bootstrap_info);
  }
  std::cout << "joining existing account" << std::endl;
  Client client_existing_account(maid_and_signer.first, bootstrap_info);
  passport::Anpmid anpmid;
  passport::Pmid pmid(anpmid);
  passport::PublicPmid public_pmid(pmid);
  std::cout << "put pmid public key on network " << HexSubstr(public_pmid.name()->string())
            << std::endl;
  client_existing_account.pimpl_->maid_node_nfs_->Put(public_pmid);
  std::this_thread::sleep_for(std::chrono::seconds(5));  // to be replaced by future.get()
  auto get_future = client_existing_account.pimpl_->maid_node_nfs_->Get(public_pmid.name());
  std::cout << " waiting to get pmid public key from network " << std::endl;
  get_future.get();
  std::cout << " RegisterVault " << std::endl;
  client_existing_account.RegisterVault(pmid);
  std::this_thread::sleep_for(std::chrono::seconds(5));
  // need to start a Vault now to Put data on network
}

}  // namespace test

}  // namespace maidsafe
