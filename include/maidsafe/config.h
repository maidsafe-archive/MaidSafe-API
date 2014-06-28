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

#ifndef MAIDSAFE_CONFIG_H_
#define MAIDSAFE_CONFIG_H_

namespace maidsafe {

#ifdef TESTING

// One of these may be called before any other operation has been done to allow all clients to
// connect to a non-production network for test purposes.
//
// To connect to a local network, you must ensure you have such a network running first.  This can
// be done using the 'local_network_controller' tool.
//
// MaidSafe will aim to always have a testnet running across multiple separate geographical
// locations to allow users to run in a sandboxed environment.
//
// These functions will throw if the network choice has already been initialised.  The choice will
// will be initialised by calling one of these functions, or initialised to the default (production
// network) by instantiating a class which connects to the network (e.g. a MaidClient).
void UseLocalNetwork();
void UseRemoteTestnet();

#endif



namespace detail {

enum class NetworkType { kProduction, kLocal, kTestnet };

NetworkType GetNetworkType();

}  // namespace detail

}  // namespace maidsafe

#endif  // MAIDSAFE_CONFIG_H_
