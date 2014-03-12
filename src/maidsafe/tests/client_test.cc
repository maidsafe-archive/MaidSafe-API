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
TEST(ClientTest, BEH_Constructor) {
  routing::Parameters::append_local_live_port_endpoint = true;
  BootstrapInfo bootstrap_info;
  passport::Anmaid anmaid;
  passport::Maid maid(anmaid);
  {
    Client client_new_account(maid, anmaid, bootstrap_info);
  }
  std::cout << "joining existing account" << std::endl;
  Client client_existing_account(maid, bootstrap_info);
}

TEST(ClientTest, BEH_RegisterVault) {
  routing::Parameters::append_local_live_port_endpoint = true;
  BootstrapInfo bootstrap_info;
  passport::Anmaid anmaid;
  passport::Maid maid(anmaid);
  {
    Client client_new_account(maid, anmaid, bootstrap_info);
  }
  std::cout << "joining existing account" << std::endl;
  Client client_existing_account(maid, bootstrap_info);
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

// Pre-condition : Need a Vault network running
// FIXME: This test will need Vault Manager to pass pmid keys to Vaults via tcp
TEST(ClientTest, BEH_StartVault) {
  const auto kVaultExePath = process::GetOtherExecutablePath(boost::filesystem::path("vault"));
  std::cout << "vault_exe_path : " << kVaultExePath.string();
  std::vector<std::string> process_args;
  process_args.push_back(kVaultExePath.string());
  process_args.push_back(" --help");
  const auto kCommandLine = process::ConstructCommandLine(process_args);
  boost::system::error_code error_code;
  bp::child child = bp::child(bp::execute(bp::initializers::run_exe(kVaultExePath),
                              bp::initializers::set_cmd_line(kCommandLine),
                              bp::initializers::set_on_error(error_code)));
  ASSERT_FALSE(error_code);
//  int exit_code(99);
  /*exit_code =*/ wait_for_exit(child, error_code);
}

}  // namespace test

}  // namespace maidsafe
