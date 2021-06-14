namespace Roydl.Crypto.Test
{
    using System;
    using System.IO;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformCross)]
    public class OthersTests
    {
        private static readonly TestCaseData[] GetGuidTestData =
        {
            new(ChecksumAlgo.Crc16, ChecksumAlgo.Crc16Usb, false, TestVarsType.TestStream, "db1fdbdb-1fdb-db1f-dbdb-1fdbdb1fdbdb"),
            new(ChecksumAlgo.Crc32, ChecksumAlgo.Sha256, false, TestVarsType.TestBytes, "2bc35bcf-ed0c-65fc-cd0e-c1553d72fb54"),
            new(ChecksumAlgo.Sha256, ChecksumAlgo.Crc32, false, TestVarsType.TestBytes, "cba33b6f-4d8c-c57c-ad4e-a1f59d329bd4"),
            new(ChecksumAlgo.Sha1, ChecksumAlgo.Crc64, false, TestVarsType.QuoteString, "a5a80644-f996-6528-f58f-9cea95e3569f"),
            new(ChecksumAlgo.Crc32, ChecksumAlgo.Sha256, false, TestVarsType.RangeString, "c52f1114-7bd6-81cb-b190-0bf72374be7f"),
            new(ChecksumAlgo.Crc32, ChecksumAlgo.Sha256, true, TestVarsType.RangeString, "{c52f1114-7bd6-81cb-b190-0bf72374be7f}")
        };

        [Test]
        [TestCase(575792, null, null)]
        [Category("Method")]
        public void CryptoUtils_CombineHashCodes(int expected, object obj1, object obj2) =>
            Assert.AreEqual(expected, CryptoUtils.CombineHashCodes(obj1, obj2));

        [Test]
        [TestCase(271354309, 10294120, 68356525)]
        public void CryptoUtils_CombineHashCodes(int expected, int hashCode1, int hashCode2) =>
            Assert.AreEqual(expected, CryptoUtils.CombineHashCodes(hashCode1, hashCode2));

        [Test]
        [Explicit]
        [Category("Extension")]
        [Platform(Include = TestVars.PlatformWin)]
        public void Extension_GetChecksums()
        {
            var items = new DirectoryInfo(@"C:\Windows\Microsoft.NET").GetChecksums();
            Assert.GreaterOrEqual(items.Count, 2383);
            foreach (var (_, checksum) in items)
                Assert.AreEqual(256 / 4, checksum.Length);
        }

        [Test]
        [TestCase(ChecksumAlgo.Crc32, ChecksumAlgo.Sha256, TestVarsType.QuoteString, "9a775baf-7038-728b-8fb4-26b9a910764a")]
        [Category("Extension")]
        [Description("Computes a CRC-32 and a SHA-256 hash and combines both to form a GUID.")]
        public void Extension_GetGuid(ChecksumAlgo _, ChecksumAlgo __, TestVarsType ___, string expectedGuid) =>
            Assert.AreEqual(expectedGuid, TestVars.QuoteStr.GetGuid());

        [Test]
        [TestCaseSource(nameof(GetGuidTestData))]
        [Category("Extension")]
        public void Extension_GetGuid(ChecksumAlgo algorithm1, ChecksumAlgo algorithm2, bool braces, TestVarsType varsType, string expectedGuid)
        {
            string guid;
            switch (varsType)
            {
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
