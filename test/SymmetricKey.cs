namespace Roydl.Crypto.Test
{
    using System;
    using Crypto.SymmetricKey;
    using NUnit.Framework;

    [TestFixture]
    public class SymmetricKey
    {
        [Test]
        [TestCase(TestOf = typeof(Aes))]
        public void AesTest()
        {
            var random = new Random();

            var bytesMap = new byte[3][];
            for (var i = 0; i < 3; i++)
            {
                var bytes = new byte[random.Next(ushort.MaxValue, 1048575)];
                random.NextBytes(bytes);
                bytesMap[i] = bytes;
            }
            Assert.IsFalse(bytesMap.Length != 3);

            var password = bytesMap[0];
            var salt = bytesMap[1];
            var secret = bytesMap[2];

            var instance = new Aes(password, salt, random.Next(1, 1048575));
            Assert.AreEqual(password, instance.Password);
            Assert.AreEqual(salt, instance.Salt);

            var encrypted = instance.EncryptBytes(secret);
            Assert.IsTrue(encrypted?.Length > 0);

            var decrypted = instance.DecryptBytes(encrypted);
            Assert.AreEqual(secret, decrypted);
        }
    }
}
