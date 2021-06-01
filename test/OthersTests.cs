namespace Roydl.Crypto.Test
{
    using System;
    using System.IO;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class OthersTests
    {
        private static readonly TestCaseData[] GetGuidTestData =
        {
            new(TestVarsType.TestStream, ChecksumAlgo.Crc16, ChecksumAlgo.Crc16Usb, false, "db1fdbdb-1fdb-db1f-dbdb-1fdbdb1fdbdb"),
            new(TestVarsType.TestBytes, ChecksumAlgo.Crc32, ChecksumAlgo.Sha256, false, "2bc35bcf-ed0c-65fc-cd0e-c1553d72fb54"),
            new(TestVarsType.TestBytes, ChecksumAlgo.Sha256, ChecksumAlgo.Crc32, false, "cba33b6f-4d8c-c57c-ad4e-a1f59d329bd4"),
            new(TestVarsType.QuoteString, ChecksumAlgo.Sha1, ChecksumAlgo.Crc64, false, "a5a80644-f996-6528-f58f-9cea95e3569f"),
            new(TestVarsType.RangeString, ChecksumAlgo.Crc32, ChecksumAlgo.Sha256, false, "c52f1114-7bd6-81cb-b190-0bf72374be7f")
        };

        [Test]
        [TestCase(575792, null, null)]
        public void CombineHashCodes(int expected, object obj1, object obj2) =>
            Assert.AreEqual(expected, CryptoUtils.CombineHashCodes(obj1, obj2));

        [Test]
        [TestCase(271354309, 10294120, 68356525)]
        public void CombineHashCodes(int expected, int hashCode1, int hashCode2) =>
            Assert.AreEqual(expected, CryptoUtils.CombineHashCodes(hashCode1, hashCode2));

        [Test]
        [TestCase(TestVarsType.QuoteString, "9a775baf-7038-728b-8fb4-26b9a910764a")]
        [Category("Extension")]
        [Description("Computes a CRC-32 and a SHA-256 hash and combines both to form a GUID.")]
        public void GetGuid(TestVarsType _, string expectedGuid) =>
            Assert.AreEqual(expectedGuid, TestVars.QuoteStr.GetGuid());

        [Test]
        [TestCaseSource(nameof(GetGuidTestData))]
        [Retry(2)]
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
