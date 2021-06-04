namespace Roydl.Crypto.Test.ChecksumTests
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
    public class Sha256Tests
    {
        private const ChecksumAlgo Algorithm = ChecksumAlgo.Sha256;
        private const int HashBits = 256;
        private const int HashSize = 64;
        private const int RawHashSize = 32;
        private const string ExpectedTestHash = "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25";
        private const string ExpectedRangeHash = "7fb98786c16c175d232ab161b5e604c5792e6befd4e1e8d4ecac9d568a6db524";
        private const string HmacExpectedTestHash = "c3e300fb7b66a2379feb536b2964c959a8f91472e3c633a636ca6df8fc471c62";
        private const string HmacExpectedRangeHash = "9d0f36cafadfe34250e18692f23301d94b0bd73c9de837a688c6756d555630d9";
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

        private static Sha256 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Sha256();
            using (var ms = new MemoryStream(TestVars.TestBytes))
                _instanceStream = new Sha256(ms);
            _instanceByteArray = new Sha256(TestVars.TestBytes);
            _instanceString = new Sha256(TestVars.TestStr);
            File.WriteAllBytes(TestFilePath, TestVars.TestBytes);
            _instanceFilePath = new Sha256(TestFilePath, true);
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
                        hash = ms.GetChecksum();
                    break;
                case TestVarsType.TestBytes:
                    hash = TestVars.TestBytes.GetChecksum();
                    break;
                case TestVarsType.TestString:
                    hash = TestVars.TestStr.GetChecksum();
                    break;
                case TestVarsType.TestFile:
                    hash = TestFilePath.GetFileChecksum();
                    break;
                case TestVarsType.RangeString:
                    hash = TestVars.RangeStr.GetChecksum();
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedHash, hash);
        }

        [Test]
        [TestCase(HashBits, HashSize, RawHashSize)]
        [Category("New")]
        public void InstanceCtor(int hashBits, int hashSize, int rawHashSize)
        {
            var instanceDefault = new Sha256();
            Assert.IsInstanceOf(typeof(Sha256), instanceDefault);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceDefault);
            Assert.AreNotSame(_instanceDefault, instanceDefault);
            Assert.AreEqual(hashBits, instanceDefault.HashBits);
            Assert.AreEqual(hashSize, instanceDefault.HashSize);
            Assert.AreEqual(rawHashSize, instanceDefault.RawHashSize);
            Assert.AreEqual(default(ReadOnlyMemory<byte>), instanceDefault.RawHash);

            Sha256 instanceStream;
            using (var ms = new MemoryStream(TestVars.TestBytes))
                instanceStream = new Sha256(ms);
            Assert.IsInstanceOf(typeof(Sha256), instanceStream);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceStream);
            Assert.AreNotSame(instanceDefault, instanceStream);
            Assert.AreEqual(hashSize, instanceStream.Hash.Length);

            var instanceByteArray = new Sha256(TestVars.TestBytes);
            Assert.IsInstanceOf(typeof(Sha256), instanceByteArray);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceByteArray);
            Assert.AreNotSame(instanceStream, instanceByteArray);
            Assert.AreEqual(hashSize, instanceByteArray.Hash.Length);

            var instanceString = new Sha256(TestVars.TestStr);
            Assert.IsInstanceOf(typeof(Sha256), instanceString);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceString);
            Assert.AreNotSame(instanceByteArray, instanceString);
            Assert.AreEqual(hashSize, instanceString.Hash.Length);

            var instanceFilePath = new Sha256(TestFilePath, true);
            Assert.IsInstanceOf(typeof(Sha256), instanceFilePath);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceFilePath);
            Assert.AreNotSame(instanceString, instanceFilePath);
            Assert.AreEqual(hashSize, instanceFilePath.Hash.Length);

            var instanceFileInfo = new Sha256(new FileInfo(TestFilePath));
            Assert.IsInstanceOf(typeof(Sha256), instanceFileInfo);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceFileInfo);
            Assert.AreNotSame(instanceString, instanceFileInfo);
            Assert.AreEqual(hashSize, instanceFileInfo.Hash.Length);

            Assert.AreEqual(instanceFilePath.HashNumber, instanceFileInfo.HashNumber);
            Assert.AreEqual(instanceFilePath.Hash, instanceFileInfo.Hash);
        }

        [Test]
        [Retry(3)]
        [MaxTime(3000)]
        [RequiresThread]
        [Category("Security")]
        public void InstanceDestroySecretKey()
        {
            var secretKey = new WeakReference(TestVars.GetRandomBytes(64));
            var instance = new Sha256
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
            Assert.AreEqual(_instanceDefault.GetHashCode(), new Sha256().GetHashCode());
            Assert.AreNotEqual(new Adler32().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<byte>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ushort>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<uint>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ulong>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<BigInteger>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Md5().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha1().GetHashCode(), _instanceDefault.GetHashCode());
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
