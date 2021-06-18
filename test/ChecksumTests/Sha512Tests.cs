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
    [Platform(Include = TestVars.PlatformCross)]
    public class Sha512Tests
    {
        private const ChecksumAlgo Algorithm = ChecksumAlgo.Sha512;
        private const int BitWidth = 512;
        private const int HashSize = BitWidth / 4;
        private const int RawHashSize = BitWidth / 8;
        private const string ExpectedTestHash = "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31";
        private const string ExpectedRangeHash = "0523f0b765970e2d2b04eb14e2f797b0c4d4b348b02dc5b7d16e49a0fdff3328ab711490b02b9fb6d7c71c7ac529e2c98c2719b7cf7561b1221b33397931af74";
        private const string HmacExpectedTestHash = "3359b5fa34b289f2bfe0a7fa592a1c5c030052e82e6e07981b2360ecbd3adffa8450856cee6ce89d2d645ff61ac3ea8a6a6ea684a316c357f9129c833545c55a";
        private const string HmacExpectedRangeHash = "2c7d58cc987034cb266b7329aac27a9f11fc3155ee56f81117440e6f4fa300412cc459da6d42aea644144623c1e7e7c73ca229c5f579b4264989510c9453d370";
        private static readonly string TestFilePath = TestVars.GetTempFilePath(Algorithm.ToString());

        private static readonly TestCaseData[] TestDataDefault =
        {
            new(Algorithm, TestSetting.Default, TestVarsType.TestStream, ExpectedTestHash),
            new(Algorithm, TestSetting.Default, TestVarsType.TestBytes, ExpectedTestHash),
            new(Algorithm, TestSetting.Default, TestVarsType.TestString, ExpectedTestHash),
            new(Algorithm, TestSetting.Default, TestVarsType.TestFile, ExpectedTestHash),
            new(Algorithm, TestSetting.Default, TestVarsType.RangeString, ExpectedRangeHash)
        };

        private static readonly TestCaseData[] TestDataHmac =
        {
            new(Algorithm, TestSetting.Hmac, TestVarsType.TestStream, HmacExpectedTestHash),
            new(Algorithm, TestSetting.Hmac, TestVarsType.TestBytes, HmacExpectedTestHash),
            new(Algorithm, TestSetting.Hmac, TestVarsType.TestString, HmacExpectedTestHash),
            new(Algorithm, TestSetting.Hmac, TestVarsType.TestFile, HmacExpectedTestHash),
            new(Algorithm, TestSetting.Hmac, TestVarsType.RangeString, HmacExpectedRangeHash)
        };

        private static Sha512 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Sha512();

            using (var ms = new MemoryStream(TestVars.TestBytes))
            {
                _instanceStream = new Sha512();
                _instanceStream.ComputeHash(ms);
            }

            _instanceByteArray = new Sha512();
            _instanceByteArray.ComputeHash(TestVars.TestBytes);

            _instanceString = new Sha512();
            _instanceString.ComputeHash(TestVars.TestStr);

            File.WriteAllBytes(TestFilePath, TestVars.TestBytes);
            _instanceFilePath = new Sha512();
            _instanceFilePath.ComputeFileHash(TestFilePath);
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
        public void Extension_GetChecksum(ChecksumAlgo _, TestSetting __, TestVarsType varsType, string expectedHash)
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
                    Assert.AreEqual(expectedHash, hash);
                    hash = new FileInfo(TestFilePath).GetChecksum(Algorithm);
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
        [TestCase(Algorithm, BitWidth, HashSize, RawHashSize)]
        [Category("New")]
        public void Instance__Ctor(ChecksumAlgo _, int bitWidth, int hashSize, int rawHashSize)
        {
            var instanceDefault = new Sha512();
            Assert.IsInstanceOf(typeof(Sha512), instanceDefault);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceDefault);
            Assert.IsNotNull(instanceDefault.AlgorithmName);
            Assert.AreEqual(bitWidth, instanceDefault.BitWidth);
            Assert.AreEqual(hashSize, instanceDefault.HashSize);
            Assert.AreEqual(rawHashSize, instanceDefault.RawHashSize);
            Assert.AreEqual(true, instanceDefault.RawHash.IsEmpty);
        }

        [Test]
        [TestCaseSource(nameof(TestDataDefault))]
        [TestCaseSource(nameof(TestDataHmac))]
        [Category("Method")]
        public void Instance_ComputeHash(ChecksumAlgo _, TestSetting setting, TestVarsType varsType, string expectedHash)
        {
            _instanceDefault.SecretKey = setting == TestSetting.Hmac ? TestVars.TestSecretKey : null;
            switch (varsType)
            {
                case TestVarsType.TestStream:
                    using (var ms = new MemoryStream(TestVars.TestBytes))
                        _instanceDefault.ComputeHash(ms);
                    break;
                case TestVarsType.TestBytes:
                    _instanceDefault.ComputeHash(TestVars.TestBytes);
                    break;
                case TestVarsType.TestString:
                    _instanceDefault.ComputeHash(TestVars.TestStr);
                    break;
                case TestVarsType.TestFile:
                    _instanceDefault.ComputeFileHash(TestFilePath);
                    Assert.AreEqual(expectedHash, _instanceDefault.Hash);
                    _instanceDefault.ComputeHash(new FileInfo(TestFilePath));
                    break;
                case TestVarsType.RangeString:
                    _instanceDefault.ComputeHash(TestVars.RangeStr);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedHash, _instanceDefault.Hash);
        }

#if RELEASE
        [Test]
        [TestCase(Algorithm)]
        [MaxTime(3000)]
        [RequiresThread]
        [Category("Security")]
        public void Instance_DestroySecretKey(ChecksumAlgo _)
        {
            var secretKey = new WeakReference(TestVars.GetRandomBytes(64));
            var instance = new Sha512((byte[])secretKey.Target);

            // Let's see if the password and salt were created correctly.
            Assert.GreaterOrEqual(instance.SecretKey?.Length, 64);
            Assert.AreEqual(secretKey.Target, instance.SecretKey);
            Assert.AreSame(secretKey.Target, instance.SecretKey);

            // Let's use the instance as usual.
            instance.ComputeHash(TestVars.RangeStr);

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
#endif

        [Test]
        [TestCase(Algorithm)]
        [Category("Method")]
        public void Instance_Equals(ChecksumAlgo _)
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
        [TestCase(Algorithm)]
        [Category("Method")]
        public void Instance_GetHashCode(ChecksumAlgo _)
        {
            Assert.AreEqual(_instanceDefault.GetHashCode(), new Sha512().GetHashCode());
            Assert.AreNotEqual(new Adler32().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<byte>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ushort>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<uint>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ulong>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<BigInteger>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Md5().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha1().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha256().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha384().GetHashCode(), _instanceDefault.GetHashCode());
        }

        [Test]
        [TestCase(Algorithm)]
        [Category("Operator")]
        public void Instance_Operators(ChecksumAlgo _)
        {
            Assert.AreEqual(ExpectedTestHash, _instanceStream.Hash);

            Assert.IsTrue(_instanceStream == _instanceByteArray);
            Assert.IsTrue(_instanceStream == _instanceString);
            Assert.IsTrue(_instanceStream == _instanceFilePath);

            Assert.IsFalse(_instanceStream != _instanceByteArray);
            Assert.IsFalse(_instanceStream != _instanceString);
            Assert.IsFalse(_instanceStream != _instanceFilePath);

            Assert.AreEqual(_instanceStream.RawHash.ToArray(), (byte[])_instanceByteArray);
            Assert.AreEqual((sbyte)(_instanceStream.CipherHash & sbyte.MaxValue), (sbyte)_instanceByteArray);
            Assert.AreEqual((byte)(_instanceStream.CipherHash & byte.MaxValue), (byte)_instanceByteArray);
            Assert.AreEqual((short)(_instanceStream.CipherHash & short.MaxValue), (short)_instanceByteArray);
            Assert.AreEqual((ushort)(_instanceStream.CipherHash & ushort.MaxValue), (ushort)_instanceByteArray);
            Assert.AreEqual((int)(_instanceStream.CipherHash & int.MaxValue), (int)_instanceByteArray);
            Assert.AreEqual((uint)(_instanceStream.CipherHash & uint.MaxValue), (uint)_instanceByteArray);
            Assert.AreEqual((long)(_instanceStream.CipherHash & long.MaxValue), (long)_instanceByteArray);
            Assert.AreEqual((ulong)(_instanceStream.CipherHash & ulong.MaxValue), (ulong)_instanceByteArray);
            Assert.AreEqual(_instanceStream.CipherHash, (BigInteger)_instanceByteArray);
            Assert.AreEqual(_instanceStream.Hash, (string)_instanceByteArray);
        }

        [Test]
        [TestCase(Algorithm)]
        [Category("Method")]
        public void Instance_ToString(ChecksumAlgo _)
        {
            Assert.AreEqual(ExpectedTestHash, _instanceStream.ToString());
            Assert.AreEqual(ExpectedTestHash, _instanceByteArray.ToString());
            Assert.AreEqual(ExpectedTestHash, _instanceString.ToString());
            Assert.AreEqual(ExpectedTestHash, _instanceFilePath.ToString());
            Assert.AreEqual(ExpectedTestHash.ToUpper(), _instanceStream.ToString(true));
        }
    }
}
