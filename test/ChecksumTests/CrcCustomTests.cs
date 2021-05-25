namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using Checksum;
    using NUnit.Framework;

    internal sealed class CrcCustom<T> : ChecksumAlgorithm<CrcCustom<T>> where T : IConvertible
    {
        private CrcConfig<T> Current { get; }

        public CrcCustom(int bits, T poly, T init, bool refIn, bool refOut, T xorOut) : base(bits) =>
            Current = new CrcConfig<T>(bits, poly, init, refIn, refOut, xorOut);

        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            Current.ComputeHash(stream, out var num);
            HashNumber = (ulong)(dynamic)num;
            RawHash = CryptoUtils.GetByteArray(HashNumber, RawHashSize);
        }
    }

    public enum CrcCustomAlgo
    {
        Crc32Jam,
        Crc32Posix
    }

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class CrcCustomTests
    {
        private static readonly TestCaseData[] TestData =
        {
            new(CrcCustomAlgo.Crc32Jam, TestVarsType.TestString, "87b22ecd"),
            new(CrcCustomAlgo.Crc32Jam, TestVarsType.RangeString, "852929ad"),
            new(CrcCustomAlgo.Crc32Posix, TestVarsType.TestString, "1e665426"),
            new(CrcCustomAlgo.Crc32Posix, TestVarsType.RangeString, "d17dacbe")
        };

        private static CrcCustom<uint> _crc32Jam, _crc32Posix;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _crc32Jam = new CrcCustom<uint>(32, 0xedb88320u, 0xffffffffu, true, true, 0x00000000u);
            _crc32Posix = new CrcCustom<uint>(32, 0x04c11db7u, 0x00000000u, false, false, 0xffffffffu);
        }

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Method")]
        public void InstanceEncrypt(CrcCustomAlgo algorithm, TestVarsType varsType, string expectedHash)
        {
            var instance = algorithm switch
            {
                CrcCustomAlgo.Crc32Jam => _crc32Jam,
                CrcCustomAlgo.Crc32Posix => _crc32Posix,
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
            };
            switch (varsType)
            {
                case TestVarsType.TestString:
                    instance.Encrypt(TestVars.TestStr);
                    break;
                case TestVarsType.RangeString:
                    instance.Encrypt(TestVars.RangeStr);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedHash, instance.Hash);
        }
    }
}
