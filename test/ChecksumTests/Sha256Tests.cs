namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [NonParallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class Sha256Tests
    {
        private const ChecksumAlgo Algorithm = ChecksumAlgo.Sha256;
        private const int HashLength = 64;
        private const string ExpectedTestHash = "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25";
        private const string ExpectedRangeHash = "7fb98786c16c175d232ab161b5e604c5792e6befd4e1e8d4ecac9d568a6db524";
        private static readonly string TestFilePath = TestVars.GetTempFilePath(Algorithm.ToString());

        private static readonly TestCaseData[] TestData =
        {
            new(TestVarsType.TestStream, ExpectedTestHash),
            new(TestVarsType.TestBytes, ExpectedTestHash),
            new(TestVarsType.TestString, ExpectedTestHash),
            new(TestVarsType.TestFile, ExpectedTestHash),
            new(TestVarsType.RangeString, ExpectedRangeHash)
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
        [TestCaseSource(nameof(TestData))]
        [Category("Extension")]
        public void ExtensionEncrypt(TestVarsType varsType, string expectedHash)
        {
            string hash;
            switch (varsType)
            {
                case TestVarsType.TestStream:
                    using (var ms = new MemoryStream(TestVars.TestBytes))
                        hash = ms.Encrypt();
                    break;
                case TestVarsType.TestBytes:
                    hash = TestVars.TestBytes.Encrypt();
                    break;
                case TestVarsType.TestString:
                    hash = TestVars.TestStr.Encrypt();
                    break;
                case TestVarsType.TestFile:
                    hash = TestFilePath.EncryptFile();
                    break;
                case TestVarsType.RangeString:
                    hash = TestVars.RangeStr.Encrypt();
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedHash, hash);
        }

        [Test]
        [TestCase(HashLength)]
        [Category("New")]
        public void InstanceCtor(int hashLength)
        {
            var instanceDefault = new Sha256();
            Assert.IsInstanceOf(typeof(Sha256), instanceDefault);
            Assert.IsInstanceOf(typeof(ChecksumAlgorithm), instanceDefault);
            Assert.AreNotSame(_instanceDefault, instanceDefault);
            Assert.AreEqual(hashLength, instanceDefault.HashSize);
            Assert.AreEqual(hashLength / 2, instanceDefault.RawHashSize);
            Assert.AreEqual(default(ReadOnlyMemory<byte>), instanceDefault.RawHash);

            Sha256 instanceStream;
            using (var ms = new MemoryStream(TestVars.TestBytes))
                instanceStream = new Sha256(ms);
            Assert.IsInstanceOf(typeof(Sha256), instanceStream);
            Assert.IsInstanceOf(typeof(ChecksumAlgorithm), instanceStream);
            Assert.AreNotSame(instanceDefault, instanceStream);
            Assert.AreEqual(hashLength, instanceStream.Hash.Length);

            var instanceByteArray = new Sha256(TestVars.TestBytes);
            Assert.IsInstanceOf(typeof(Sha256), instanceByteArray);
            Assert.IsInstanceOf(typeof(ChecksumAlgorithm), instanceByteArray);
            Assert.AreNotSame(instanceStream, instanceByteArray);
            Assert.AreEqual(hashLength, instanceByteArray.Hash.Length);

            var instanceString = new Sha256(TestVars.TestStr);
            Assert.IsInstanceOf(typeof(Sha256), instanceString);
            Assert.IsInstanceOf(typeof(ChecksumAlgorithm), instanceString);
            Assert.AreNotSame(instanceByteArray, instanceString);
            Assert.AreEqual(hashLength, instanceString.Hash.Length);

            var instanceFilePath = new Sha256(TestFilePath, true);
            Assert.IsInstanceOf(typeof(Sha256), instanceFilePath);
            Assert.IsInstanceOf(typeof(ChecksumAlgorithm), instanceFilePath);
            Assert.AreNotSame(instanceString, instanceFilePath);
            Assert.AreEqual(hashLength, instanceFilePath.Hash.Length);
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
            Assert.AreEqual(_instanceDefault.GetHashCode(), _instanceStream.GetHashCode());
            Assert.AreEqual(_instanceDefault.GetHashCode(), _instanceByteArray.GetHashCode());
            Assert.AreEqual(_instanceDefault.GetHashCode(), _instanceString.GetHashCode());
            Assert.AreEqual(_instanceDefault.GetHashCode(), _instanceFilePath.GetHashCode());
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
