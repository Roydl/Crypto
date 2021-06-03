namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class Adler32Tests
    {
        private const ChecksumAlgo Algorithm = ChecksumAlgo.Adler32;
        private const int HashBits = 32;
        private const int HashSize = 8;
        private const int RawHashSize = 4;
        private const string ExpectedTestHash = "03dd01a1";
        private const string ExpectedRangeHash = "f923cf3f";
        private static readonly string TestFilePath = TestVars.GetTempFilePath(Algorithm.ToString());

        private static readonly TestCaseData[] TestData =
        {
            new(TestVarsType.TestStream, ExpectedTestHash),
            new(TestVarsType.TestBytes, ExpectedTestHash),
            new(TestVarsType.TestString, ExpectedTestHash),
            new(TestVarsType.TestFile, ExpectedTestHash),
            new(TestVarsType.RangeString, ExpectedRangeHash)
        };

        private static Adler32 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Adler32();
            using (var ms = new MemoryStream(TestVars.TestBytes))
                _instanceStream = new Adler32(ms);
            _instanceByteArray = new Adler32(TestVars.TestBytes);
            _instanceString = new Adler32(TestVars.TestStr);
            File.WriteAllBytes(TestFilePath, TestVars.TestBytes);
            _instanceFilePath = new Adler32(TestFilePath, true);
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
        [TestCaseSource(nameof(TestData))]
        [Category("Extension")]
        public void ExtensionEncrypt(TestVarsType varsType, string expectedHash)
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
        [TestCaseSource(nameof(TestData))]
        [Category("Extension")]
        public void ExtensionGetCipher(TestVarsType varsType, string expectedHash)
        {
            ulong hash;
            switch (varsType)
            {
                case TestVarsType.TestStream:
                    using (var ms = new MemoryStream(TestVars.TestBytes))
                        hash = ms.GetCipher(Algorithm);
                    break;
                case TestVarsType.TestBytes:
                    hash = TestVars.TestBytes.GetCipher(Algorithm);
                    break;
                case TestVarsType.TestString:
                    hash = TestVars.TestStr.GetCipher(Algorithm);
                    break;
                case TestVarsType.TestFile:
                    hash = File.ReadAllBytes(TestFilePath).GetCipher(Algorithm);
                    break;
                case TestVarsType.RangeString:
                    hash = TestVars.RangeStr.GetCipher(Algorithm);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(Convert.ToUInt64(expectedHash, 16), hash);
        }

        [Test]
        [TestCase(HashBits, HashSize, RawHashSize)]
        [Category("New")]
        public void InstanceCtor(int hashBits, int hashSize, int rawHashSize)
        {
            var instanceDefault = new Adler32();
            Assert.IsInstanceOf(typeof(Adler32), instanceDefault);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceDefault);
            Assert.AreNotSame(_instanceDefault, instanceDefault);
            Assert.AreEqual(hashBits, instanceDefault.HashBits);
            Assert.AreEqual(hashSize, instanceDefault.HashSize);
            Assert.AreEqual(rawHashSize, instanceDefault.RawHashSize);
            Assert.AreEqual(default(ReadOnlyMemory<byte>), instanceDefault.RawHash);

            Adler32 instanceStream;
            using (var ms = new MemoryStream(TestVars.TestBytes))
                instanceStream = new Adler32(ms);
            Assert.IsInstanceOf(typeof(Adler32), instanceStream);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceStream);
            Assert.AreNotSame(instanceDefault, instanceStream);
            Assert.AreEqual(hashSize, instanceStream.Hash.Length);

            var instanceByteArray = new Adler32(TestVars.TestBytes);
            Assert.IsInstanceOf(typeof(Adler32), instanceByteArray);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceByteArray);
            Assert.AreNotSame(instanceStream, instanceByteArray);
            Assert.AreEqual(hashSize, instanceByteArray.Hash.Length);

            var instanceString = new Adler32(TestVars.TestStr);
            Assert.IsInstanceOf(typeof(Adler32), instanceString);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceString);
            Assert.AreNotSame(instanceByteArray, instanceString);
            Assert.AreEqual(hashSize, instanceString.Hash.Length);

            var instanceFilePath = new Adler32(TestFilePath, true);
            Assert.IsInstanceOf(typeof(Adler32), instanceFilePath);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceFilePath);
            Assert.AreNotSame(instanceString, instanceFilePath);
            Assert.AreEqual(hashSize, instanceFilePath.Hash.Length);

            var instanceFileInfo = new Adler32(new FileInfo(TestFilePath));
            Assert.IsInstanceOf(typeof(Adler32), instanceFileInfo);
            Assert.IsInstanceOf(typeof(IChecksumAlgorithm), instanceFileInfo);
            Assert.AreNotSame(instanceString, instanceFileInfo);
            Assert.AreEqual(hashSize, instanceFileInfo.Hash.Length);

            Assert.AreEqual(instanceFilePath.HashNumber, instanceFileInfo.HashNumber);
            Assert.AreEqual(instanceFilePath.Hash, instanceFileInfo.Hash);
        }

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Method")]
        public void InstanceEncrypt(TestVarsType varsType, string expectedHash)
        {
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
            Assert.AreEqual(_instanceDefault.GetHashCode(), new Adler32().GetHashCode());
            Assert.AreNotEqual(new Crc16().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc17().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc21().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc24().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc30().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc31().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc32().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc40().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc64().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Crc82().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Md5().GetHashCode(), _instanceDefault.GetHashCode());
            Assert.AreNotEqual(new Sha1().GetHashCode(), _instanceDefault.GetHashCode());
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
            Assert.AreEqual(_instanceStream.HashNumber, (uint)_instanceByteArray);
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
