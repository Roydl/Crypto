﻿namespace Roydl.Crypto.Test.SymmetricKeyTests
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using SymmetricKey;
    using Rijndael = SymmetricKey.Rijndael;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformCross)]
    public class RijndaelTests
    {
        public enum SymmetricKeyAlgo
        {
            Rijndael
        }

        private const SymmetricKeyAlgo Algorithm = SymmetricKeyAlgo.Rijndael;
        private static readonly string TestFileSrcPath = TestVars.GetTempFilePath(nameof(Rijndael));
        private static readonly string TestFileDestPath = TestVars.GetTempFilePath(nameof(Rijndael));

        private static readonly TestCaseData[] TestData =
        {
            new(Algorithm, TestVarsType.TestStream),
            new(Algorithm, TestVarsType.TestBytes),
            new(Algorithm, TestVarsType.TestString),
            new(Algorithm, TestVarsType.TestFile),
            new(Algorithm, TestVarsType.RangeString)
        };

        private static Rijndael _instance128, _instance192, _instance256;

        [OneTimeSetUp]
        public void CreateInstance()
        {
            _instance128 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), SymmetricKeySize.Small, SymmetricKey.SymmetricKeyAlgo.Sha1);
            _instance192 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), SymmetricKeySize.Medium);
            _instance256 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), SymmetricKeySize.Large, SymmetricKey.SymmetricKeyAlgo.Sha512);
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
        [TestCase(Algorithm)]
        [Category("New")]
        public void Instance__Ctor(SymmetricKeyAlgo _)
        {
            var instance128 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), SymmetricKeySize.Small, SymmetricKey.SymmetricKeyAlgo.Sha1);
            Assert.IsInstanceOf(typeof(Rijndael), instance128);
            Assert.IsInstanceOf(typeof(SymmetricKeyAlgorithm), instance128);
            Assert.Greater(instance128.Iterations, 0);
            Assert.AreEqual(128, instance128.BlockSize);
            Assert.AreEqual(128, (int)instance128.KeySize);
            Assert.AreEqual(160, (int)instance128.KeyAlgo);
            Assert.AreEqual(BlockCipherMode.Cbc, instance128.Mode);
            Assert.AreEqual(BlockPaddingMode.Pkcs7, instance128.Padding);
            Assert.AreEqual((int)CipherMode.CBC, (int)instance128.Mode);
            Assert.AreEqual((int)PaddingMode.PKCS7, (int)instance128.Padding);
            Assert.NotNull(instance128.Password);
            Assert.NotNull(instance128.Salt);

            var instance192 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), SymmetricKeySize.Medium);
            Assert.IsInstanceOf(typeof(Rijndael), instance192);
            Assert.IsInstanceOf(typeof(SymmetricKeyAlgorithm), instance192);
            Assert.Greater(instance192.Iterations, 0);
            Assert.AreEqual(128, instance192.BlockSize);
            Assert.AreEqual(192, (int)instance192.KeySize);
            Assert.AreEqual(256, (int)instance192.KeyAlgo);
            Assert.AreEqual(BlockCipherMode.Cbc, instance192.Mode);
            Assert.AreEqual(BlockPaddingMode.Pkcs7, instance192.Padding);
            Assert.AreEqual((int)CipherMode.CBC, (int)instance192.Mode);
            Assert.AreEqual((int)PaddingMode.PKCS7, (int)instance192.Padding);
            Assert.NotNull(instance192.Password);
            Assert.NotNull(instance192.Salt);

            var instance256 = new Rijndael(TestVars.GetRandomBytes(), TestVars.GetRandomBytes(), TestVars.GetRandomInt(), SymmetricKeySize.Large, SymmetricKey.SymmetricKeyAlgo.Sha512);
            Assert.IsInstanceOf(typeof(Rijndael), instance256);
            Assert.IsInstanceOf(typeof(SymmetricKeyAlgorithm), instance256);
            Assert.Greater(instance256.Iterations, 0);
            Assert.AreEqual(128, instance256.BlockSize);
            Assert.AreEqual(256, (int)instance256.KeySize);
            Assert.AreEqual(512, (int)instance256.KeyAlgo);
            Assert.AreEqual(BlockCipherMode.Cbc, instance256.Mode);
            Assert.AreEqual(BlockPaddingMode.Pkcs7, instance256.Padding);
            Assert.AreEqual((int)CipherMode.CBC, (int)instance256.Mode);
            Assert.AreEqual((int)PaddingMode.PKCS7, (int)instance256.Padding);
            Assert.NotNull(instance256.Password);
            Assert.NotNull(instance256.Salt);
        }

#if RELEASE
        [Test]
        [TestCase(Algorithm)]
        [MaxTime(3000)]
        [RequiresThread]
        [Category("Security")]
        public void Instance_DestroySecretData(SymmetricKeyAlgo _)
        {
            var pass = new WeakReference(TestVars.GetRandomBytes(256));
            var salt = new WeakReference(TestVars.GetRandomBytes(128));
            var inst = new Rijndael((byte[])pass.Target, (byte[])salt.Target, TestVars.GetRandomInt());

            // Let's see if the password and salt were created correctly.
            Assert.AreEqual(256, inst.Password.Count);
            Assert.AreEqual(128, inst.Salt.Count);
            Assert.AreEqual(pass.Target, inst.Password);
            Assert.AreEqual(salt.Target, inst.Salt);
            Assert.AreSame(pass.Target, inst.Password);
            Assert.AreSame(salt.Target, inst.Salt);

            // Let's use the instance as usual.
            var original = TestVars.GetRandomBytes();
            var encrypted = inst.Encrypt(original);
            var decrypted = inst.Decrypt(encrypted);
            Assert.AreEqual(original, decrypted);

            // Time to remove password and salt from process memory.
            inst.DestroySecretData();
            Assert.IsNull(inst.Password);
            Assert.IsNull(inst.Salt);

            // This takes a few milliseconds. 
            while (pass.IsAlive || salt.IsAlive)
                Task.Delay(1);

            // Now we will see if all secret data has been removed from the process memory.
            Assert.IsNull(pass.Target);
            Assert.IsNull(salt.Target);
            Assert.IsFalse(pass.IsAlive);
            Assert.IsFalse(salt.IsAlive);
        }
#endif

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Method")]
        public void Instance_Encrypt_Decrypt(SymmetricKeyAlgo _, TestVarsType varsType)
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
                            instance.Encrypt(msi, mso);
                            encrypted = mso.ToArray();
                        }

                        // decrypt
                        using (var msi = new MemoryStream(encrypted))
                        {
                            using var mso = new MemoryStream();
                            instance.Decrypt(msi, mso);
                            decrypted = mso.ToArray();
                        }
                        break;
                    case TestVarsType.TestBytes:
                        original = TestVars.TestBytes;
                        encrypted = instance.Encrypt((byte[])original);
                        decrypted = instance.Decrypt(encrypted);
                        break;
                    case TestVarsType.TestString:
                        original = Encoding.UTF8.GetBytes(TestVars.TestStr);
                        encrypted = instance.Encrypt((byte[])original);
                        decrypted = instance.Decrypt(encrypted);
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
                        encrypted = instance.Encrypt((byte[])original);
                        decrypted = instance.Decrypt(encrypted);
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
