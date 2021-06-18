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
    public class Sha384Tests
    {
        private const ChecksumAlgo Algorithm = ChecksumAlgo.Sha384;
        private const int BitWidth = 384;
        private const int HashSize = BitWidth / 4;
        private const int RawHashSize = BitWidth / 8;
        private const string ExpectedTestHash = "7b8f4654076b80eb963911f19cfad1aaf4285ed48e826f6cde1b01a79aa73fadb5446e667fc4f90417782c91270540f3";
        private const string ExpectedRangeHash = "dd39f42bdb371db2efbaa9d7ed505c332c42e7a900960a8a40fe4890e4de4bb83fa633417844bf1fec41ba9b46a1a522";
        private const string HmacExpectedTestHash = "e7ca02e47635a2dcadb00d55c3582caa30b8a4a180ea9d9500ba935353d745e80ba0cc1450dbf971575e6629f749d01b";
        private const string HmacExpectedRangeHash = "8518a4e907a75f0059fd265f26219b5731cb4c961e3bcca1bed8017cb29bbd7ea193e69687d418bde01a79cb9749b8bf";
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

        private static Sha384 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Sha384();

            using (var ms = new MemoryStream(TestVars.TestBytes))
            {
                _instanceStream = new Sha384();
                _instanceStream.ComputeHash(ms);
            }

            _instanceByteArray = new Sha384();
            _instanceByteArray.ComputeHash(TestVars.TestBytes);

            _instanceString = new Sha384();
            _instanceString.ComputeHash(TestVars.TestStr);

            File.WriteAllBytes(TestFilePath, TestVars.TestBytes);
            _instanceFilePath = new Sha384();
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
            var instanceDefault = new Sha384();
            Assert.IsInstanceOf(typeof(Sha384), instanceDefault);
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
            var instance = new Sha384((byte[])secretKey.Target);

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
            Assert.AreEqual(_instanceDefault.GetHashCode(), new Sha384().GetHashCode());
            Assert.AreNotEqual(new Adler32().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<byte>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ushort>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<uint>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<ulong>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc<BigInteger>().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Md5().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha1().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha256().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha512().GetHashCode(), _instanceDefault.GetHashCode());
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
