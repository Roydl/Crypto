namespace Roydl.Crypto.Test
{
    using NUnit.Framework;

    [TestFixture]
    [NonParallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class CryptoExtensionstTests
    {
        private static readonly TestCaseData[] GetGuidTestData =
        {
            new("{ac4410f7-ac44-10f7-0000-ac4410f70000}", TestVars.QuoteStr, true, ChecksumAlgo.Adler32, ChecksumAlgo.Crc16),
            new("0000d4b3-c852-cafd-9bcd-6f1412be1539", TestVars.QuoteStr, false, ChecksumAlgo.Crc16, ChecksumAlgo.Md5),
            new("8cd3f7b5-a99b-d111-a253-d111a253ded5", TestVars.QuoteStr, false, ChecksumAlgo.Sha1, ChecksumAlgo.Crc64),
        };

        [Test]
        [Category("Extension")]
        [Description("Computes a CRC-32 and a SHA-256 hash and combines both to form a GUID.")]
        public void GetGuid() =>
            Assert.AreEqual("75edf6dd-8ffa-edd2-652d-2ef5cd3269ac", TestVars.QuoteStr.GetGuid());

        [Test]
        [TestCaseSource(nameof(GetGuidTestData))]
        [Category("Extension")]
        public void GetGuid(string expected, string input, bool braces, ChecksumAlgo algorithm1, ChecksumAlgo algorithm2) =>
            Assert.AreEqual(expected, input.GetGuid(braces, algorithm1, algorithm2));
    }
}
