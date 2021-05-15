namespace Roydl.Crypto.Test
{
    using System;
    using System.IO;
    using NUnit.Framework;

    [TestFixture]
    [NonParallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class OthersTests
    {
        private static readonly TestCaseData[] GetGuidTestData =
        {
            new(TestVarsType.TestStream, ChecksumAlgo.Crc32, ChecksumAlgo.Sha256, false, "784dd132-532e-aabd-9574-7a6e0f345e25"),
            new(TestVarsType.TestBytes, ChecksumAlgo.Crc32, ChecksumAlgo.Sha256, false, "784dd132-532e-aabd-9574-7a6e0f345e25"),
            new(TestVarsType.QuoteString, ChecksumAlgo.Crc16, ChecksumAlgo.Md5, false, "0000d4b3-c852-cafd-9bcd-6f1412be1539"),
            new(TestVarsType.QuoteString, ChecksumAlgo.Sha1, ChecksumAlgo.Crc64, false, "8cd3f7b5-a99b-d111-a253-d111a253ded5"),
            new(TestVarsType.QuoteString, ChecksumAlgo.Adler32, ChecksumAlgo.Crc16, true, "{ac4410f7-ac44-10f7-0000-ac4410f70000}"),
            new(TestVarsType.RangeString, ChecksumAlgo.Crc32, ChecksumAlgo.Sha256, false, "7ad6d652-7fb9-8786-c16c-9d568a6db524")
        };

        [Test]
        [TestCase(575792, null, null)]
        public void CombineHashCodes(int expected, object obj1, object obj2) => Assert.AreEqual(expected, CryptoUtils.CombineHashCodes(obj1, obj2));

        [Test]
        [TestCase(271354309, 10294120, 68356525)]
        public void CombineHashCodes(int expected, int hashCode1, int hashCode2) => Assert.AreEqual(expected, CryptoUtils.CombineHashCodes(hashCode1, hashCode2));

        [Test]
        [TestCase(TestVarsType.QuoteString, "75edf6dd-8ffa-edd2-652d-2ef5cd3269ac")]
        [Category("Extension")]
        [Description("Computes a CRC-32 and a SHA-256 hash and combines both to form a GUID.")]
        public void GetGuid(TestVarsType _, string expectedGuid) =>
            Assert.AreEqual(expectedGuid, TestVars.QuoteStr.GetGuid());

        [Test]
        [TestCaseSource(nameof(GetGuidTestData))]
        [Category("Extension")]
        public void GetGuid(TestVarsType varsType, ChecksumAlgo algorithm1, ChecksumAlgo algorithm2, bool braces, string expectedGuid)
        {
            string guid;
            switch (varsType)
            {
                case TestVarsType.TestFile:
                    // No extension for file paths
                    return;
                case TestVarsType.TestStream:
                    using (var ms = new MemoryStream(TestVars.TestBytes))
                        guid = ms.GetGuid(braces, algorithm1, algorithm2);
                    break;
                case TestVarsType.TestBytes:
                    guid = TestVars.TestBytes.GetGuid(braces, algorithm1, algorithm2);
                    break;
                case TestVarsType.TestString:
                    guid = TestVars.TestStr.GetGuid(braces, algorithm1, algorithm2);
                    break;
                case TestVarsType.QuoteString:
                    guid = TestVars.QuoteStr.GetGuid(braces, algorithm1, algorithm2);
                    break;
                case TestVarsType.RangeString:
                    guid = TestVars.RangeStr.GetGuid(braces, algorithm1, algorithm2);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedGuid, guid);
        }
    }
}
