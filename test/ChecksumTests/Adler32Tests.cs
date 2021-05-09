﻿namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using AbstractSamples;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = Vars.PlatformInclude)]
    public class Adler32Tests
    {
        private const ChecksumAlgorithm Algorithm = ChecksumAlgorithm.Adler32;
        private const int HashLength = 8;
        private const uint DefaultRawHash = 0u;
        private const string ExpectedTestHash = "03dd01a1";
        private const string ExpectedRangeHash = "f923cf3f";
        private const string TestFilePath = ".\\testFileChecksum.Adler32";

        private static readonly TestCaseData[] TestData =
        {
            new(TestDataVarsType.TestStream, ExpectedTestHash),
            new(TestDataVarsType.TestBytes, ExpectedTestHash),
            new(TestDataVarsType.TestString, ExpectedTestHash),
            new(TestDataVarsType.TestFile, ExpectedTestHash),
            new(TestDataVarsType.RangeString, ExpectedRangeHash)
        };

        private static Adler32 _instanceDefault, _instanceStream, _instanceByteArray, _instanceString, _instanceFilePath;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instanceDefault = new Adler32();
            using (var ms = new MemoryStream(Vars.TestBytes))
                _instanceStream = new Adler32(ms);
            _instanceByteArray = new Adler32(Vars.TestBytes);
            _instanceString = new Adler32(Vars.TestStr);
            File.WriteAllBytes(TestFilePath, Vars.TestBytes);
            _instanceFilePath = new Adler32(TestFilePath, true);
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
        public void InstanceCtor(int hashLength, uint defaultRawHash)
        {
            var instanceDefault = new Adler32();
            Assert.IsInstanceOf(typeof(Adler32), instanceDefault);
            Assert.IsInstanceOf(typeof(ChecksumSample), instanceDefault);
            Assert.AreNotSame(_instanceDefault, instanceDefault);
            Assert.AreEqual(hashLength, instanceDefault.HashLength);
            Assert.AreEqual(hashLength, instanceDefault.Hash.Length);
            Assert.AreEqual(defaultRawHash, instanceDefault.RawHash);

            Adler32 instanceStream;
            using (var ms = new MemoryStream(Vars.TestBytes))
                instanceStream = new Adler32(ms);
            Assert.IsInstanceOf(typeof(Adler32), instanceStream);
            Assert.IsInstanceOf(typeof(ChecksumSample), instanceStream);
            Assert.AreNotSame(instanceDefault, instanceStream);
            Assert.AreEqual(hashLength, instanceStream.Hash.Length);
            Assert.AreNotEqual(defaultRawHash, instanceStream.RawHash);

            var instanceByteArray = new Adler32(Vars.TestBytes);
            Assert.IsInstanceOf(typeof(Adler32), instanceByteArray);
            Assert.IsInstanceOf(typeof(ChecksumSample), instanceByteArray);
            Assert.AreNotSame(instanceStream, instanceByteArray);
            Assert.AreEqual(hashLength, instanceByteArray.Hash.Length);
            Assert.AreNotEqual(defaultRawHash, instanceByteArray.RawHash);

            var instanceString = new Adler32(Vars.TestStr);
            Assert.IsInstanceOf(typeof(Adler32), instanceString);
            Assert.IsInstanceOf(typeof(ChecksumSample), instanceString);
            Assert.AreNotSame(instanceByteArray, instanceString);
            Assert.AreEqual(hashLength, instanceString.Hash.Length);
            Assert.AreNotEqual(defaultRawHash, instanceString.RawHash);

            var instanceFilePath = new Adler32(TestFilePath, true);
            Assert.IsInstanceOf(typeof(Adler32), instanceFilePath);
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