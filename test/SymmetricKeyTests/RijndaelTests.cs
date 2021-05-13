namespace Roydl.Crypto.Test.SymmetricKeyTests
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using NUnit.Framework;
    using SymmetricKey;
    using Rijndael = SymmetricKey.Rijndael;

    [TestFixture]
    [NonParallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class RijndaelTests
    {
        private static readonly string TestFileSrcPath = TestVars.GetTempFilePath(nameof(Rijndael));
        private static readonly string TestFileDestPath = TestVars.GetTempFilePath(nameof(Rijndael));

        private static readonly TestCaseData[] TestData =
        {
            new(TestVarsType.TestStream),
            new(TestVarsType.TestBytes),
            new(TestVarsType.TestString),
            new(TestVarsType.TestFile),
            new(TestVarsType.RangeString)
        };

        private static Rijndael _instance128, _instance192, _instance256;

        [OneTimeSetUp]
        public void CreateInstance()
        {
            _instance128 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), RijndaelKeySize.Aes128);
            _instance192 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), RijndaelKeySize.Aes192);
            _instance256 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt());
            File.WriteAllText(TestFileSrcPath, TestVars.TestStr);
        }

        [OneTimeTearDown]
        public void CleanUpTestFiles()
        {
            var dir = Path.GetDirectoryName(TestFileSrcPath);
            if (dir == null)
                return;
            foreach (var file in Directory.GetFiles(dir, $"test-{nameof(Rijndael)}-*.tmp"))
                File.Delete(file);
        }

        [Test]
        [Category("New")]
        public void InstanceCtor()
        {
            var instance128 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), RijndaelKeySize.Aes128);
            Assert.IsInstanceOf(typeof(Rijndael), instance128);
            Assert.IsInstanceOf(typeof(SymmetricKeyAlgorithm), instance128);
            Assert.Greater(instance128.Iterations, 0);
            Assert.AreEqual(128, instance128.BlockSize);
            Assert.AreEqual(128, instance128.KeySize);
            Assert.AreEqual(CipherMode.CBC, instance128.Mode);
            Assert.AreEqual(PaddingMode.PKCS7, instance128.Padding);
            Assert.NotNull(instance128.Password);
            Assert.NotNull(instance128.Salt);

            var instance192 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), RijndaelKeySize.Aes192);
            Assert.IsInstanceOf(typeof(Rijndael), instance192);
            Assert.IsInstanceOf(typeof(SymmetricKeyAlgorithm), instance192);
            Assert.Greater(instance192.Iterations, 0);
            Assert.AreEqual(128, instance192.BlockSize);
            Assert.AreEqual(192, instance192.KeySize);
            Assert.AreEqual(CipherMode.CBC, instance192.Mode);
            Assert.AreEqual(PaddingMode.PKCS7, instance192.Padding);
            Assert.NotNull(instance192.Password);
            Assert.NotNull(instance192.Salt);

            var instance256 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt());
            Assert.IsInstanceOf(typeof(Rijndael), instance256);
            Assert.IsInstanceOf(typeof(SymmetricKeyAlgorithm), instance256);
            Assert.Greater(instance256.Iterations, 0);
            Assert.AreEqual(128, instance256.BlockSize);
            Assert.AreEqual(256, instance256.KeySize);
            Assert.AreEqual(CipherMode.CBC, instance256.Mode);
            Assert.AreEqual(PaddingMode.PKCS7, instance256.Padding);
            Assert.NotNull(instance256.Password);
            Assert.NotNull(instance256.Salt);
        }

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Method")]
        public void InstanceEncryptDecrypt(TestVarsType varsType)
        {
            foreach (var instance in new[] { _instance128, _instance192, _instance256 })
            {
                object original, decrypted;
                byte[] encrypted;
                switch (varsType)
                {
                    case TestVarsType.TestStream:
                        original = TestVars.TestBytes;

                        // encrypt
                        using (var msi = new MemoryStream((byte[])original))
                        {
                            using var mso = new MemoryStream();
                            instance.EncryptStream(msi, mso);
                            encrypted = mso.ToArray();
                        }

                        // decrypt
                        using (var msi = new MemoryStream(encrypted))
                        {
                            using var mso = new MemoryStream();
                            instance.DecryptStream(msi, mso);
                            decrypted = mso.ToArray();
                        }
                        break;
                    case TestVarsType.TestBytes:
                        original = TestVars.TestBytes;
                        encrypted = instance.EncryptBytes((byte[])original);
                        decrypted = instance.DecryptBytes(encrypted);
                        break;
                    case TestVarsType.TestString:
                        original = Encoding.UTF8.GetBytes(TestVars.TestStr);
                        encrypted = instance.EncryptBytes((byte[])original);
                        decrypted = instance.DecryptBytes(encrypted);
                        break;
                    case TestVarsType.TestFile:
                        Assert.IsTrue(instance.EncryptFile(TestFileSrcPath, TestFileDestPath));
                        Assert.IsTrue(instance.DecryptFile(TestFileDestPath, TestFileSrcPath));
                        original = TestVars.TestBytes;
                        encrypted = instance.EncryptFile(TestFileSrcPath);
                        decrypted = instance.DecryptFile(TestFileDestPath);
                        break;
                    case TestVarsType.RangeString:
                        original = Encoding.UTF8.GetBytes(TestVars.RangeStr);
                        encrypted = instance.EncryptBytes((byte[])original);
                        decrypted = instance.DecryptBytes(encrypted);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
                }
                Assert.NotNull(encrypted);
                Assert.AreEqual(original, decrypted);
            }
        }
    }
}
