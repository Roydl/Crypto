namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using System.Numerics;
    using Checksum;
    using NUnit.Framework;
#if RELEASE
    using System.Threading.Tasks;
#endif

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformCross)]
    public class Sha3Bit256Tests
    {
        private const ChecksumAlgo Algorithm = ChecksumAlgo.Sha3;
        private const int BitWidth = 256;
        private const int HashSize = BitWidth / 4;
        private const int RawHashSize = BitWidth / 8;
        private const string ExpectedTestHash = "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0";
        private const string ExpectedRangeHash = "e8e7e13c3ebdcf3f866b9df2bf973bbd2d4fffbd0268e0d2bcdc5049682b43be";
        private const string HmacExpectedTestHash = "d1ffd3c6682ee7ae79ef994432c5379f90046c7ee58b30ac2a4655bf2ec45e06";
        private const string HmacExpectedRangeHash = "41bc5646fa1bbd4cad022378444d8e619b5669a15eec20e1c13f9c71c7ad9b58";
        private static readonly string TestFilePath = TestVars.GetTempFilePath(Algorithm.ToString());

        private static readonly TestCaseData[] TestDataDefault =
        [
            new(Algorithm, TestSetting.Default, TestVarsType.TestStream, ExpectedTestHash),
            new(Algorithm, TestSetting.Default, TestVarsType.TestBytes, ExpectedTestHash),
            new(Algorithm, TestSetting.Default, TestVarsType.TestString, ExpectedTestHash),
            new(Algorithm, TestSetting.Default, TestVarsType.TestFile, ExpectedTestHash),
            new(Algorithm, TestSetting.Default, TestVarsType.RangeString, ExpectedRangeHash)
        ];

        private static readonly TestCaseData[] TestDataHmac =
        [
            new(Algorithm, TestSetting.Hmac, TestVarsType.TestStream, HmacExpectedTestHash),
            new(Algorithm, TestSetting.Hmac, TestVarsType.TestBytes, HmacExpectedTestHash),
            new(Algorithm, TestSetting.Hmac, TestVarsType.TestString, HmacExpectedTestHash),
            new(Algorithm, TestSetting.Hmac, TestVarsType.TestFile, HmacExpectedTestHash),
            new(Algorithm, TestSetting.Hmac, TestVarsType.RangeString, HmacExpectedRangeHash)
        ];

        private static Sha3 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Sha3();

            using (var ms = new MemoryStream(TestVars.TestBytes))
            {
                _instanceStream = new Sha3();
                _instanceStream.ComputeHash(ms);
            }

            _instanceByteArray = new Sha3();
            _instanceByteArray.ComputeHash(TestVars.TestBytes);

            _instanceString = new Sha3();
            _instanceString.ComputeHash(TestVars.TestStr);

            File.WriteAllBytes(TestFilePath, TestVars.TestBytes);
            _instanceFilePath = new Sha3();
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
                        hash = ms.GetChecksum(ChecksumAlgo.Sha3);
                    break;
                case TestVarsType.TestBytes:
                    hash = TestVars.TestBytes.GetChecksum(ChecksumAlgo.Sha3);
                    break;
                case TestVarsType.TestString:
                    hash = TestVars.TestStr.GetChecksum(ChecksumAlgo.Sha3);
                    break;
                case TestVarsType.TestFile:
                    hash = TestFilePath.GetFileChecksum(ChecksumAlgo.Sha3);
                    Assert.AreEqual(expectedHash, hash);
                    hash = new FileInfo(TestFilePath).GetChecksum(ChecksumAlgo.Sha3);
                    break;
                case TestVarsType.RangeString:
                    hash = TestVars.RangeStr.GetChecksum(ChecksumAlgo.Sha3);
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
            var instanceDefault = new Sha3();
            Assert.IsInstanceOf<Sha3>(instanceDefault);
            Assert.IsInstanceOf<IChecksumAlgorithm>(instanceDefault);
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
            var instance = new Sha3((byte[])secretKey.Target);

            // Let's see if the password and salt were created correctly.
            Assert.GreaterOrEqual(instance.SecretKey?.Length ?? 0, 64);
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
            Assert.AreEqual(_instanceDefault.GetHashCode(), new Sha3().GetHashCode());
            Assert.AreNotEqual(new Adler32().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<byte>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ushort>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<uint>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ulong>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<BigInteger>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Md5().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha1().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha2().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha2Bit384().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha2Bit512().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha3Bit384().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha3Bit512().GetHashCode(), _instanceDefault.GetHashCode());
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
