/*  Copyright 2015 MaidSafe.net limited

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

#include "maidsafe/directory_info.h"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/serialisation/serialisation.h"

namespace maidsafe {

namespace test {

testing::AssertionResult Matches(const DirectoryInfo& expected, const DirectoryInfo& actual) {
  return (expected.path == actual.path && expected.parent_id == actual.parent_id &&
          expected.directory_id == actual.directory_id &&
          expected.access_rights == actual.access_rights) ?
             testing::AssertionSuccess() :
             testing::AssertionFailure();
}

TEST(DirectoryInfoTest, BEH_ConstructAndAssign) {
  // Default c'tor
  ASSERT_NO_THROW(DirectoryInfo());
  const DirectoryInfo directory_info;
  EXPECT_TRUE(directory_info.path.empty());
  EXPECT_FALSE(directory_info.parent_id.IsInitialised());
  EXPECT_FALSE(directory_info.directory_id.IsInitialised());

  // C'tor taking value
  const DirectoryInfo directory_info1(
      RandomAlphaNumericString(100), Identity{RandomAlphaNumericBytes(identity_size)},
      Identity{RandomAlphaNumericBytes(identity_size)}, DirectoryInfo::AccessRights::kReadOnly);
  const DirectoryInfo directory_info2(
      RandomAlphaNumericString(100), Identity{RandomAlphaNumericBytes(identity_size)},
      Identity{RandomAlphaNumericBytes(identity_size)}, DirectoryInfo::AccessRights::kReadWrite);

  // Copy and move
  DirectoryInfo copied(directory_info1);
  EXPECT_TRUE(Matches(directory_info1, copied));

  DirectoryInfo moved(std::move(copied));
  EXPECT_TRUE(Matches(directory_info1, moved));

  copied = directory_info2;
  EXPECT_TRUE(Matches(directory_info2, copied));

  moved = std::move(copied);
  EXPECT_TRUE(Matches(directory_info2, moved));
}

TEST(DirectoryInfoTest, BEH_Serialisation) {
  const DirectoryInfo directory_info(
      RandomAlphaNumericString(100), Identity{RandomAlphaNumericBytes(identity_size)},
      Identity{RandomAlphaNumericBytes(identity_size)}, DirectoryInfo::AccessRights::kReadOnly);
  auto serialised = Serialise(directory_info);
  auto parsed = Parse<DirectoryInfo>(serialised);
  EXPECT_TRUE(Matches(directory_info, parsed));
}

}  // namespace test

}  // namespace maidsafe
