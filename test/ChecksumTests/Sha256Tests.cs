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
    [Platform(Include = TestVars.PlatformCross)]
    public class Sha256Tests
    {
        private const ChecksumAlgo Algorithm = ChecksumAlgo.Sha256;
        private const int BitWidth = 256;
        private const int HashSize = BitWidth / 4;
        private const int RawHashSize = BitWidth / 8;
        private const string ExpectedTestHash = "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25";
        private const string ExpectedRangeHash = "7fb98786c16c175d232ab161b5e604c5792e6befd4e1e8d4ecac9d568a6db524";
        private const string HmacExpectedTestHash = "c3e300fb7b66a2379feb536b2964c959a8f91472e3c633a636ca6df8fc471c62";
        private const string HmacExpectedRangeHash = "9d0f36cafadfe34250e18692f23301d94b0bd73c9de837a688c6756d555630d9";
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

        private static Sha256 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Sha256();

            using (var ms = new MemoryStream(TestVars.TestBytes))
            {
                _instanceStream = new Sha256();
                _instanceStream.ComputeHash(ms);
            }

            _instanceByteArray = new Sha256();
            _instanceByteArray.ComputeHash(TestVars.TestBytes);

            _instanceString = new Sha256();
            _instanceString.ComputeHash(TestVars.TestStr);

            File.WriteAllBytes(TestFilePath, TestVars.TestBytes);
            _instanceFilePath = new Sha256();
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
                    Assert.AreEqual(expectedHash, hash);
                    hash = new FileInfo(TestFilePath).GetChecksum();
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
        [TestCase(Algorithm, BitWidth, HashSize, RawHashSize)]
        [Category("New")]
        public void Instance__Ctor(ChecksumAlgo _, int bitWidth, int hashSize, int rawHashSize)
        {
            var instanceDefault = new Sha256();
            Assert.IsInstanceOf(typeof(Sha256), instanceDefault);
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
            var instance = new Sha256((byte[])secretKey.Target);

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
