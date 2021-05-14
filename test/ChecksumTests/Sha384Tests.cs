namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [NonParallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class Sha384Tests
    {
        private const ChecksumAlgo Algorithm = ChecksumAlgo.Sha384;
        private const int HashLength = 96;
        private const string ExpectedTestHash = "7b8f4654076b80eb963911f19cfad1aaf4285ed48e826f6cde1b01a79aa73fadb5446e667fc4f90417782c91270540f3";
        private const string ExpectedRangeHash = "dd39f42bdb371db2efbaa9d7ed505c332c42e7a900960a8a40fe4890e4de4bb83fa633417844bf1fec41ba9b46a1a522";
        private static readonly string TestFilePath = TestVars.GetTempFilePath(Algorithm.ToString());

        private static readonly TestCaseData[] TestData =
        {
            new(TestVarsType.TestStream, ExpectedTestHash),
            new(TestVarsType.TestBytes, ExpectedTestHash),
            new(TestVarsType.TestString, ExpectedTestHash),
            new(TestVarsType.TestFile, ExpectedTestHash),
            new(TestVarsType.RangeString, ExpectedRangeHash)
        };

        private static Sha384 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Sha384();
            using (var ms = new MemoryStream(TestVars.TestBytes))
                _instanceStream = new Sha384(ms);
            _instanceByteArray = new Sha384(TestVars.TestBytes);
            _instanceString = new Sha384(TestVars.TestStr);
            File.WriteAllBytes(TestFilePath, TestVars.TestBytes);
            _instanceFilePath = new Sha384(TestFilePath, true);
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
                        hash = ms.Encrypt(Algorithm);
                    break;
                case TestVarsType.TestBytes:
                    hash = TestVars.TestBytes.Encrypt(Algorithm);
                    break;
                case TestVarsType.TestString:
                    hash = TestVars.TestStr.Encrypt(Algorithm);
                    break;
                case TestVarsType.TestFile:
                    hash = TestFilePath.EncryptFile(Algorithm);
                    break;
                case TestVarsType.RangeString:
                    hash = TestVars.RangeStr.Encrypt(Algorithm);
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
            var instanceDefault = new Sha384();
            Assert.IsInstanceOf(typeof(Sha384), instanceDefault);
            Assert.IsInstanceOf(typeof(ChecksumAlgorithm), instanceDefault);
            Assert.AreNotSame(_instanceDefault, instanceDefault);
            Assert.AreEqual(hashLength, instanceDefault.HashSize);
            Assert.AreEqual(hashLength / 2, instanceDefault.RawHashSize);
            Assert.AreEqual(default(ReadOnlyMemory<byte>), instanceDefault.RawHash);

            Sha384 instanceStream;
            using (var ms = new MemoryStream(TestVars.TestBytes))
                instanceStream = new Sha384(ms);
            Assert.IsInstanceOf(typeof(Sha384), instanceStream);
            Assert.IsInstanceOf(typeof(ChecksumAlgorithm), instanceStream);
            Assert.AreNotSame(instanceDefault, instanceStream);
            Assert.AreEqual(hashLength, instanceStream.Hash.Length);

            var instanceByteArray = new Sha384(TestVars.TestBytes);
            Assert.IsInstanceOf(typeof(Sha384), instanceByteArray);
            Assert.IsInstanceOf(typeof(ChecksumAlgorithm), instanceByteArray);
            Assert.AreNotSame(instanceStream, instanceByteArray);
            Assert.AreEqual(hashLength, instanceByteArray.Hash.Length);

            var instanceString = new Sha384(TestVars.TestStr);
            Assert.IsInstanceOf(typeof(Sha384), instanceString);
            Assert.IsInstanceOf(typeof(ChecksumAlgorithm), instanceString);
            Assert.AreNotSame(instanceByteArray, instanceString);
            Assert.AreEqual(hashLength, instanceString.Hash.Length);

            var instanceFilePath = new Sha384(TestFilePath, true);
            Assert.IsInstanceOf(typeof(Sha384), instanceFilePath);
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
