using System;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.AspNet.Identity;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace Oogi2.Identity.Tests
{
    [TestClass]
    public class UserStoreTests
    {        
        [Attributes.EntityType("entity", "oogi2.identity")]
        public class SuperIdentityUser : IdentityUser
        {            
        }

        Connection _con;
        UserStore<SuperIdentityUser> _userStore;

        [TestInitialize]
        public void Init()
        {
            var appSettings = new ConfigurationBuilder()
               .SetBasePath(Directory.GetCurrentDirectory())
               .AddJsonFile("appsettings.json")
               .AddUserSecrets("oogi2")
               .AddEnvironmentVariables()
               .Build();

            _con = new Connection(appSettings["endpoint"], appSettings["authorizationKey"], appSettings["database"], appSettings["collection"]);
            _con.CreateCollection();
            _userStore = new UserStore<SuperIdentityUser>(_con);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _con.DeleteCollection();
        }

        [TestMethod]
        public async Task CreateUserAsync()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-1",
                Email = "test.user.1@test.com"
            };

            await _userStore.CreateAsync(testUser);

            var savedUser = await _userStore.FindByEmailAsync(testUser.Email);

            Assert.IsNotNull(savedUser);
            Assert.AreEqual(testUser.Email, savedUser.Email);
        }

        [TestMethod]
        public async Task UpdatesAreAppliedToUser()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-2",
                Email = "test.user.2@test.com"
            };

            await _userStore.CreateAsync(testUser);

            var savedUser = await _userStore.FindByEmailAsync(testUser.Email);

            if (savedUser == null)
                throw new NullReferenceException("savedUser");

            savedUser.EmailConfirmed = true;

            await _userStore.UpdateAsync(savedUser);

            savedUser = await _userStore.FindByEmailAsync(testUser.Email);

            Assert.IsNotNull(savedUser);
            Assert.IsTrue(savedUser.EmailConfirmed);
        }

        [TestMethod]
        public async Task UsersWithCustomIdsPersistThroughStorageAsync()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-3",
                Email = "test.user.3@test.com",
                Id = "test-user-id-3"
            };

            await _userStore.CreateAsync(testUser);

            var savedUser = await _userStore.FindByEmailAsync(testUser.Email);

            Assert.IsNotNull(savedUser);
            Assert.AreEqual(testUser.Id, savedUser.Id);
        }

        [TestMethod]
        public async Task UsersWithNoSetIdDefaultToNewGuidAsync()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-4",
                Email = "test.user.4@test.com"
            };

            await _userStore.CreateAsync(testUser);

            var savedUser = await _userStore.FindByEmailAsync(testUser.Email);
            Assert.IsTrue(!string.IsNullOrEmpty(savedUser.Id));

            Guid guidId;
            Assert.IsTrue(Guid.TryParse(savedUser.Id, out guidId));
        }

        [TestMethod]
        public async Task CanFindUserByLoginInfoAsync()
        {
            var testUser = new SuperIdentityUser
            {
                UserName = "test-user-5",
                Email = "test.user.5@test.com"
            };

            await _userStore.CreateAsync(testUser);

            var user = await _userStore.FindByEmailAsync(testUser.Email);
            Assert.IsNotNull(user);

            var loginInfo = new UserLoginInfo("ATestLoginProvider", "ATestKey292929");
            await _userStore.AddLoginAsync(user, loginInfo);

            var userByLoginInfo = await _userStore.FindAsync(loginInfo);

            Assert.IsNotNull(userByLoginInfo);
        }        
    }
}
