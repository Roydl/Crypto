namespace Roydl.Crypto.Test.SymmetricKeyTests
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using AbstractSamples;
    using NUnit.Framework;
    using SymmetricKey;
    using Aes = SymmetricKey.Aes;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = Vars.PlatformInclude)]
    public class AesTests
    {
        private const string TestFileSrcPath = ".\\testSymmetricKey.Src.Aes";
        private const string TestFileDestPath = ".\\testSymmetricKey.Dest.Aes";
        public static readonly string RangeStr = Vars.RangeStr;

        private static readonly TestCaseData[] TestData =
        {
            new(TestDataVarsType.TestStream),
            new(TestDataVarsType.TestBytes),
            new(TestDataVarsType.TestString),
            new(TestDataVarsType.TestFile),
            new(TestDataVarsType.RangeString)
        };

        private static Aes _instance128, _instance192, _instance256;

        [OneTimeSetUp]
        public void CreateInstance()
        {
            _instance128 = new Aes(Vars.GetRandomBytes(), Vars.GetRandomBytes(), Vars.GetRandomInt(), AesKeySize.Aes128);
            _instance192 = new Aes(Vars.GetRandomBytes(), Vars.GetRandomBytes(), Vars.GetRandomInt(), AesKeySize.Aes192);
            _instance256 = new Aes(Vars.GetRandomBytes(), Vars.GetRandomBytes(), Vars.GetRandomInt());
            File.WriteAllText(TestFileSrcPath, Vars.TestStr);
        }

        [OneTimeSetUp]
        public void ProcessExit()
        {
            AppDomain.CurrentDomain.ProcessExit += RemoveTestFile;

            static void RemoveTestFile(object sender, EventArgs args)
            {
                if (File.Exists(TestFileSrcPath))
                    File.Delete(TestFileSrcPath);
                if (File.Exists(TestFileDestPath))
                    File.Delete(TestFileDestPath);
            }
        }

        [Test]
        [Category("New")]
        public void InstanceCtor()
        {
            var instance128 = new Aes(Vars.GetRandomBytes(), Vars.GetRandomBytes(), Vars.GetRandomInt(), AesKeySize.Aes128);
            Assert.IsInstanceOf(typeof(Aes), instance128);
            Assert.IsInstanceOf(typeof(SymmetricKeySample), instance128);
            Assert.Greater(instance128.Iterations, 0);
            Assert.AreEqual(128, instance128.BlockSize);
            Assert.AreEqual(128, instance128.KeySize);
            Assert.AreEqual(CipherMode.CBC, instance128.Mode);
            Assert.AreEqual(PaddingMode.PKCS7, instance128.Padding);
            Assert.NotNull(instance128.Password);
            Assert.NotNull(instance128.Salt);

            var instance192 = new Aes(Vars.GetRandomBytes(), Vars.GetRandomBytes(), Vars.GetRandomInt(), AesKeySize.Aes192);
            Assert.IsInstanceOf(typeof(Aes), instance192);
            Assert.IsInstanceOf(typeof(SymmetricKeySample), instance192);
            Assert.Greater(instance192.Iterations, 0);
            Assert.AreEqual(128, instance192.BlockSize);
            Assert.AreEqual(192, instance192.KeySize);
            Assert.AreEqual(CipherMode.CBC, instance192.Mode);
            Assert.AreEqual(PaddingMode.PKCS7, instance192.Padding);
            Assert.NotNull(instance192.Password);
            Assert.NotNull(instance192.Salt);

            var instance256 = new Aes(Vars.GetRandomBytes(), Vars.GetRandomBytes(), Vars.GetRandomInt());
            Assert.IsInstanceOf(typeof(Aes), instance256);
            Assert.IsInstanceOf(typeof(SymmetricKeySample), instance256);
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
        public void InstanceEncryptDecrypt(TestDataVarsType varsType)
        {
            foreach (var instance in new[] { _instance128, _instance192, _instance256 })
            {
                object original, decrypted;
                byte[] encrypted;
                switch (varsType)
                {
                    case TestDataVarsType.TestStream:
                        original = Vars.TestBytes;

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
                    case TestDataVarsType.TestBytes:
                        original = Vars.TestBytes;
                        encrypted = instance.EncryptBytes((byte[])original);
                        decrypted = instance.DecryptBytes(encrypted);
                        break;
                    case TestDataVarsType.TestString:
                        original = Encoding.UTF8.GetBytes(Vars.TestStr);
                        encrypted = instance.EncryptBytes((byte[])original);
                        decrypted = instance.DecryptBytes(encrypted);
                        break;
                    case TestDataVarsType.TestFile:
                        Assert.IsTrue(instance.EncryptFile(TestFileSrcPath, TestFileDestPath));
                        Assert.IsTrue(instance.DecryptFile(TestFileDestPath, TestFileSrcPath));
                        original = Vars.TestBytes;
                        encrypted = instance.EncryptFile(TestFileSrcPath);
                        decrypted = instance.DecryptFile(TestFileDestPath);
                        break;
                    case TestDataVarsType.QuoteString:
                        original = Encoding.UTF8.GetBytes(Vars.QuoteStr);
                        encrypted = instance.EncryptBytes((byte[])original);
                        decrypted = instance.DecryptBytes(encrypted);
                        break;
                    case TestDataVarsType.RangeString:
                        original = Encoding.UTF8.GetBytes(Vars.RangeStr);
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

        [Test]
        [Category("Method")]
        public void InstanceGetHashCode()
        {
            Assert.AreNotEqual(0, _instance128.GetHashCode());
            Assert.AreNotEqual(0, _instance192.GetHashCode());
            Assert.AreNotEqual(0, _instance256.GetHashCode());
        }

        [Test]
        [Category("Method")]
        public void InstanceToString()
        {
            Assert.AreEqual("Roydl.Crypto.SymmetricKey.Aes", _instance128.ToString());
            Assert.AreEqual("Roydl.Crypto.SymmetricKey.Aes", _instance192.ToString());
            Assert.AreEqual("Roydl.Crypto.SymmetricKey.Aes", _instance256.ToString());
        }
    }
}
