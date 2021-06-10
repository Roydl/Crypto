﻿namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using System.Numerics;
    using System.Threading.Tasks;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class Sha1Tests
    {
        private const ChecksumAlgo Algorithm = ChecksumAlgo.Sha1;
        private const int BitWidth = 160;
        private const int HashSize = 40;
        private const int RawHashSize = 20;
        private const string ExpectedTestHash = "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa";
        private const string ExpectedRangeHash = "60dd4bf59289437e8f18bfbadb6613072d5c6f2c";
        private const string HmacExpectedTestHash = "c57e24093841d97e5462cab3957d455392c283dc";
        private const string HmacExpectedRangeHash = "22642a046bbd2876e49a788e45aaa3d665ccacce";
        private static readonly string TestFilePath = TestVars.GetTempFilePath(Algorithm.ToString());

        private static readonly TestCaseData[] TestDataDefault =
        {
            new(TestSetting.Default, TestVarsType.TestStream, ExpectedTestHash),
            new(TestSetting.Default, TestVarsType.TestBytes, ExpectedTestHash),
            new(TestSetting.Default, TestVarsType.TestString, ExpectedTestHash),
            new(TestSetting.Default, TestVarsType.TestFile, ExpectedTestHash),
            new(TestSetting.Default, TestVarsType.RangeString, ExpectedRangeHash)
        };

        private static readonly TestCaseData[] TestDataHmac =
        {
            new(TestSetting.Hmac, TestVarsType.TestStream, HmacExpectedTestHash),
            new(TestSetting.Hmac, TestVarsType.TestBytes, HmacExpectedTestHash),
            new(TestSetting.Hmac, TestVarsType.TestString, HmacExpectedTestHash),
            new(TestSetting.Hmac, TestVarsType.TestFile, HmacExpectedTestHash),
            new(TestSetting.Hmac, TestVarsType.RangeString, HmacExpectedRangeHash)
        };

        private static Sha1 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Sha1();

            using (var ms = new MemoryStream(TestVars.TestBytes))
            {
                _instanceStream = new Sha1();
                _instanceStream.Encrypt(ms);
            }

            _instanceByteArray = new Sha1();
            _instanceByteArray.Encrypt(TestVars.TestBytes);

            _instanceString = new Sha1();
            _instanceString.Encrypt(TestVars.TestStr);

            File.WriteAllBytes(TestFilePath, TestVars.TestBytes);
            _instanceFilePath = new Sha1();
            _instanceFilePath.EncryptFile(TestFilePath);
        }

        [OneTimeTearDown]
        public void CleanUpTestFiles()
        {
            var dir = Path.GetDirectoryName(TestFilePath);
            if (dir == null)
                return;
            foreach (var file in Directory.GetFiles(dir, $"test-{Algorithm}-*.tmp"))
                File.Delete(file);
        }

        [Test]
        [TestCaseSource(nameof(TestDataDefault))]
        [Category("Extension")]
        public void ExtensionEncrypt(TestSetting _, TestVarsType varsType, string expectedHash)
        {
            string hash;
            switch (varsType)
            {
                case TestVarsType.TestStream:
                    using (var ms = new MemoryStream(TestVars.TestBytes))
                        hash = ms.GetChecksum(Algorithm);
                    break;
                case TestVarsType.TestBytes:
                    hash = TestVars.TestBytes.GetChecksum(Algorithm);
                    break;
                case TestVarsType.TestString:
                    hash = TestVars.TestStr.GetChecksum(Algorithm);
                    break;
                case TestVarsType.TestFile:
                    hash = TestFilePath.GetFileChecksum(Algorithm);
                    break;
                case TestVarsType.RangeString:
                    hash = TestVars.RangeStr.GetChecksum(Algorithm);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedHash, hash);
        }

        [Test]
        [TestCase(BitWidth, HashSize, RawHashSize)]
        [Category("New")]
        public void InstanceCtor(int bitWidth, int hashSize, int rawHashSize)
        {
            var instanceDefault = new Sha1();
            Assert.IsInstanceOf(typeof(Sha1), instanceDefault);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceDefault);
            Assert.AreNotSame(_instanceDefault, instanceDefault);
            Assert.AreEqual(bitWidth, instanceDefault.BitWidth);
            Assert.AreEqual(hashSize, instanceDefault.HashSize);
            Assert.AreEqual(rawHashSize, instanceDefault.RawHashSize);
            Assert.AreEqual(default(ReadOnlyMemory<byte>), instanceDefault.RawHash);
        }

        [Test]
        [Retry(3)]
        [MaxTime(3000)]
        [RequiresThread]
        [Category("Security")]
        public void InstanceDestroySecretKey()
        {
            var secretKey = new WeakReference(TestVars.GetRandomBytes(64));
            var instance = new Sha1
            {
                SecretKey = (byte[])secretKey.Target
            };

            // Let's see if the password and salt were created correctly.
            Assert.GreaterOrEqual(instance.SecretKey?.Length, 64);
            Assert.AreEqual(secretKey.Target, instance.SecretKey);
            Assert.AreSame(secretKey.Target, instance.SecretKey);

            // Let's use the instance as usual.
            instance.Encrypt(TestVars.RangeStr);

            // Time to remove secret key from process memory.
            instance.DestroySecretKey();
            Assert.IsNull(instance.SecretKey);

            // This takes a few milliseconds. 
            while (secretKey.IsAlive)
                Task.Delay(1);

            // Now we will see if all secret key has been removed from the process memory.
            Assert.IsNull(secretKey.Target);
            Assert.IsFalse(secretKey.IsAlive);
        }

        [Test]
        [TestCaseSource(nameof(TestDataDefault))]
        [TestCaseSource(nameof(TestDataHmac))]
        [Category("Method")]
        public void InstanceEncrypt(TestSetting setting, TestVarsType varsType, string expectedHash)
        {
            _instanceDefault.SecretKey = setting == TestSetting.Hmac ? TestVars.TestSecretKey : null;
            switch (varsType)
            {
                case TestVarsType.TestStream:
                    using (var ms = new MemoryStream(TestVars.TestBytes))
                        _instanceDefault.Encrypt(ms);
                    break;
                case TestVarsType.TestBytes:
                    _instanceDefault.Encrypt(TestVars.TestBytes);
                    break;
                case TestVarsType.TestString:
                    _instanceDefault.Encrypt(TestVars.TestStr);
                    break;
                case TestVarsType.TestFile:
                    _instanceDefault.EncryptFile(TestFilePath);
                    Assert.AreEqual(expectedHash, _instanceDefault.Hash);
                    _instanceDefault.Encrypt(new FileInfo(TestFilePath));
                    break;
                case TestVarsType.RangeString:
                    _instanceDefault.Encrypt(TestVars.RangeStr);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedHash, _instanceDefault.Hash);
        }

        [Test]
        [Category("Method")]
        public void InstanceEquals()
        {
            Assert.AreEqual(ExpectedTestHash, _instanceStream.Hash);

            Assert.IsTrue(_instanceStream.Equals((object)_instanceByteArray));
            Assert.IsTrue(_instanceStream.Equals(_instanceByteArray));

            Assert.IsTrue(_instanceStream.Equals((object)_instanceString));
            Assert.IsTrue(_instanceStream.Equals(_instanceString));

            Assert.IsTrue(_instanceStream.Equals((object)_instanceFilePath));
            Assert.IsTrue(_instanceStream.Equals(_instanceFilePath));
        }

        [Test]
        [Category("Method")]
        public void InstanceGetHashCode()
        {
            Assert.AreEqual(_instanceDefault.GetHashCode(), new Sha1().GetHashCode());
            Assert.AreNotEqual(new Adler32().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<byte>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ushort>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<uint>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ulong>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<BigInteger>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Md5().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha256().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha384().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha512().GetHashCode(), _instanceDefault.GetHashCode());
        }

        [Test]
        [Category("Operator")]
        public void InstanceOperators()
        {
            Assert.AreEqual(ExpectedTestHash, _instanceStream.Hash);

            Assert.IsTrue(_instanceStream == _instanceByteArray);
            Assert.IsTrue(_instanceStream == _instanceString);
            Assert.IsTrue(_instanceStream == _instanceFilePath);

            Assert.IsFalse(_instanceStream != _instanceByteArray);
            Assert.IsFalse(_instanceStream != _instanceString);
            Assert.IsFalse(_instanceStream != _instanceFilePath);

            Assert.AreEqual(_instanceStream.RawHash.Span.ToArray(), (byte[])_instanceByteArray);
            Assert.AreEqual((short)(_instanceStream.HashNumber & short.MaxValue), (short)_instanceByteArray);
            Assert.AreEqual((ushort)(_instanceStream.HashNumber & ushort.MaxValue), (ushort)_instanceByteArray);
            Assert.AreEqual((int)(_instanceStream.HashNumber & int.MaxValue), (int)_instanceByteArray);
            Assert.AreEqual((uint)(_instanceStream.HashNumber & uint.MaxValue), (uint)_instanceByteArray);
            Assert.AreEqual((long)(_instanceStream.HashNumber & long.MaxValue), (long)_instanceByteArray);
            Assert.AreEqual((ulong)(_instanceStream.HashNumber & ulong.MaxValue), (ulong)_instanceByteArray);
            Assert.AreEqual((nint)(long)(_instanceStream.HashNumber & long.MaxValue), (nint)_instanceByteArray);
            Assert.AreEqual((nuint)(ulong)(_instanceStream.HashNumber & ulong.MaxValue), (nuint)_instanceByteArray);
            Assert.AreEqual(_instanceStream.HashNumber, (BigInteger)_instanceByteArray);
            Assert.AreEqual(_instanceStream.Hash, (string)_instanceByteArray);
        }

        [Test]
        [Category("Method")]
        public void InstanceToString()
        {
            Assert.AreEqual(ExpectedTestHash, _instanceStream.ToString());
            Assert.AreEqual(ExpectedTestHash, _instanceByteArray.ToString());
            Assert.AreEqual(ExpectedTestHash, _instanceString.ToString());
            Assert.AreEqual(ExpectedTestHash, _instanceFilePath.ToString());
            Assert.AreEqual(ExpectedTestHash.ToUpper(), _instanceStream.ToString(true));
        }
    }
}
