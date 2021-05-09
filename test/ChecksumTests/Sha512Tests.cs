namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using AbstractSamples;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = Vars.PlatformInclude)]
    public class Sha512Tests
    {
        private const ChecksumAlgorithm Algorithm = ChecksumAlgorithm.Sha512;
        private const int HashLength = 128;
        private const byte[] DefaultRawHash = null;
        private const string ExpectedTestHash = "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31";
        private const string ExpectedRangeHash = "0523f0b765970e2d2b04eb14e2f797b0c4d4b348b02dc5b7d16e49a0fdff3328ab711490b02b9fb6d7c71c7ac529e2c98c2719b7cf7561b1221b33397931af74";
        private static readonly string TestFilePath = Vars.GetTempFilePath();

        private static readonly TestCaseData[] TestData =
        {
            new(TestDataVarsType.TestStream, ExpectedTestHash),
            new(TestDataVarsType.TestBytes, ExpectedTestHash),
            new(TestDataVarsType.TestString, ExpectedTestHash),
            new(TestDataVarsType.TestFile, ExpectedTestHash),
            new(TestDataVarsType.RangeString, ExpectedRangeHash)
        };

        private static Sha512 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Sha512();
            using (var ms = new MemoryStream(Vars.TestBytes))
                _instanceStream = new Sha512(ms);
            _instanceByteArray = new Sha512(Vars.TestBytes);
            _instanceString = new Sha512(Vars.TestStr);
            File.WriteAllBytes(TestFilePath, Vars.TestBytes);
            _instanceFilePath = new Sha512(TestFilePath, true);
        }

        [OneTimeSetUp]
        public void ProcessExit()
        {
            AppDomain.CurrentDomain.ProcessExit += RemoveTestFile;

            static void RemoveTestFile(object sender, EventArgs args)
            {
                if (File.Exists(TestFilePath))
                    File.Delete(TestFilePath);
            }
        }

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Extension")]
        public void ExtensionEncrypt(TestDataVarsType varsType, string expectedHash)
        {
            string hash;
            switch (varsType)
            {
                case TestDataVarsType.TestStream:
                    using (var ms = new MemoryStream(Vars.TestBytes))
                        hash = ms.Encrypt(Algorithm);
                    break;
                case TestDataVarsType.TestBytes:
                    hash = Vars.TestBytes.Encrypt(Algorithm);
                    break;
                case TestDataVarsType.TestString:
                    hash = Vars.TestStr.Encrypt(Algorithm);
                    break;
                case TestDataVarsType.TestFile:
                    hash = TestFilePath.EncryptFile(Algorithm);
                    break;
                case TestDataVarsType.QuoteString:
                    hash = Vars.QuoteStr.Encrypt(Algorithm);
                    break;
                case TestDataVarsType.RangeString:
                    hash = Vars.RangeStr.Encrypt(Algorithm);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedHash, hash);
        }

        [Test]
        [TestCase(HashLength, DefaultRawHash)]
        [Category("New")]
        public void InstanceCtor(int hashLength, byte[] defaultRawHash)
        {
            var instanceDefault = new Sha512();
            Assert.IsInstanceOf(typeof(Sha512), instanceDefault);
            Assert.IsInstanceOf(typeof(ChecksumSample), instanceDefault);
            Assert.AreNotSame(_instanceDefault, instanceDefault);
            Assert.AreEqual(hashLength, instanceDefault.HashLength);
            Assert.AreEqual(hashLength, instanceDefault.Hash.Length);
            Assert.AreEqual(defaultRawHash, instanceDefault.RawHash);

            Sha512 instanceStream;
            using (var ms = new MemoryStream(Vars.TestBytes))
                instanceStream = new Sha512(ms);
            Assert.IsInstanceOf(typeof(Sha512), instanceStream);
            Assert.IsInstanceOf(typeof(ChecksumSample), instanceStream);
            Assert.AreNotSame(instanceDefault, instanceStream);
            Assert.AreEqual(hashLength, instanceStream.Hash.Length);
            Assert.AreNotEqual(defaultRawHash, instanceStream.RawHash);

            var instanceByteArray = new Sha512(Vars.TestBytes);
            Assert.IsInstanceOf(typeof(Sha512), instanceByteArray);
            Assert.IsInstanceOf(typeof(ChecksumSample), instanceByteArray);
            Assert.AreNotSame(instanceStream, instanceByteArray);
            Assert.AreEqual(hashLength, instanceByteArray.Hash.Length);
            Assert.AreNotEqual(defaultRawHash, instanceByteArray.RawHash);

            var instanceString = new Sha512(Vars.TestStr);
            Assert.IsInstanceOf(typeof(Sha512), instanceString);
            Assert.IsInstanceOf(typeof(ChecksumSample), instanceString);
            Assert.AreNotSame(instanceByteArray, instanceString);
            Assert.AreEqual(hashLength, instanceString.Hash.Length);
            Assert.AreNotEqual(defaultRawHash, instanceString.RawHash);

            var instanceFilePath = new Sha512(TestFilePath, true);
            Assert.IsInstanceOf(typeof(Sha512), instanceFilePath);
            Assert.IsInstanceOf(typeof(ChecksumSample), instanceFilePath);
            Assert.AreNotSame(instanceString, instanceFilePath);
            Assert.AreEqual(hashLength, instanceFilePath.Hash.Length);
            Assert.AreNotEqual(defaultRawHash, instanceFilePath.RawHash);
        }

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Method")]
        public void InstanceEncrypt(TestDataVarsType varsType, string expectedHash)
        {
            switch (varsType)
            {
                case TestDataVarsType.TestStream:
                    using (var ms = new MemoryStream(Vars.TestBytes))
                        _instanceDefault.Encrypt(ms);
                    break;
                case TestDataVarsType.TestBytes:
                    _instanceDefault.Encrypt(Vars.TestBytes);
                    break;
                case TestDataVarsType.TestString:
                    _instanceDefault.Encrypt(Vars.TestStr);
                    break;
                case TestDataVarsType.TestFile:
                    _instanceDefault.EncryptFile(TestFilePath);
                    break;
                case TestDataVarsType.QuoteString:
                    _instanceDefault.Encrypt(Vars.QuoteStr);
                    break;
                case TestDataVarsType.RangeString:
                    _instanceDefault.Encrypt(Vars.RangeStr);
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
        }
    }
}
