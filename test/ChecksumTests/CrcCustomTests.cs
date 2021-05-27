namespace Roydl.Crypto.Test.ChecksumTests
{
    using System;
    using System.IO;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class CrcCustomTests
    {
        public sealed class CrcCustom<T> : ChecksumAlgorithm<CrcCustom<T>> where T : IConvertible, IFormattable
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

        public enum CrcPreset
        {
            Crc08,
            Crc10,
            Crc11,
            Crc12Dect,
            Crc13Bbc,
            Crc14Darc,
            Crc15,
            Crc15Mpt1327,
            Crc16Usb,
            Crc24,
            Crc24FlexrayA,
            Crc24FlexrayB,
            Crc31Philips,
            Crc32Jam,
            Crc32Posix,
            Crc40Gsm,
            Crc64We,
            Crc64Xz
        }

        private static readonly TestCaseData[] TestData =
        {
            new(CrcPreset.Crc08, TestVarsType.TestString, "77"),
            new(CrcPreset.Crc10, TestVarsType.TestString, "30"),
            new(CrcPreset.Crc11, TestVarsType.TestString, "bf"),
            new(CrcPreset.Crc12Dect, TestVarsType.TestString, "5e"),
            new(CrcPreset.Crc13Bbc, TestVarsType.TestString, "66"),
            new(CrcPreset.Crc14Darc, TestVarsType.TestString, "aa"),

            new(CrcPreset.Crc15, TestVarsType.TestString, "53"),
            new(CrcPreset.Crc15, TestVarsType.RangeString, "dc"),

            new(CrcPreset.Crc15Mpt1327, TestVarsType.TestString, "0f"),
            new(CrcPreset.Crc15Mpt1327, TestVarsType.RangeString, "f8"),

            new(CrcPreset.Crc16Usb, TestVarsType.TestString, "e3da"),
            new(CrcPreset.Crc16Usb, TestVarsType.RangeString, "9354"),

            new(CrcPreset.Crc24, TestVarsType.TestString, "20777c"),
            new(CrcPreset.Crc24, TestVarsType.RangeString, "38c4f4"),

            new(CrcPreset.Crc24FlexrayA, TestVarsType.TestString, "2c70f2"),
            new(CrcPreset.Crc24FlexrayA, TestVarsType.RangeString, "294438"),

            new(CrcPreset.Crc24FlexrayB, TestVarsType.TestString, "0e3a1d"),
            new(CrcPreset.Crc24FlexrayB, TestVarsType.RangeString, "d5ee31"),

            new(CrcPreset.Crc31Philips, TestVarsType.TestString, "76718d"),
            new(CrcPreset.Crc31Philips, TestVarsType.RangeString, "e0c69c"),

            new(CrcPreset.Crc32Jam, TestVarsType.TestString, "87b22ecd"),
            new(CrcPreset.Crc32Jam, TestVarsType.RangeString, "852929ad"),

            new(CrcPreset.Crc32Posix, TestVarsType.TestString, "1e665426"),
            new(CrcPreset.Crc32Posix, TestVarsType.RangeString, "d17dacbe"),

            new(CrcPreset.Crc40Gsm, TestVarsType.TestString, "10df47b471"),
            new(CrcPreset.Crc40Gsm, TestVarsType.RangeString, "f46d283fad"),

            new(CrcPreset.Crc64We, TestVarsType.TestString, "d00f8e47e656f4d0"),
            new(CrcPreset.Crc64We, TestVarsType.RangeString, "eafb40d259d5882c"),

            new(CrcPreset.Crc64Xz, TestVarsType.TestString, "6275e834da84732f"),
            new(CrcPreset.Crc64Xz, TestVarsType.RangeString, "2472ea52fe9d7cf0")
        };

        private static object[] _instances;

        [OneTimeSetUp]
        public void CreateInstances()
        {
            _instances = new object[Enum.GetNames(typeof(CrcPreset)).Length];
            _instances[(int)CrcPreset.Crc08] = new CrcCustom<byte>(8, 0x07, 0x00, false, false, 0x00);
            _instances[(int)CrcPreset.Crc10] = new CrcCustom<short>(10, 0x233, 0x00, false, false, 0x00);
            _instances[(int)CrcPreset.Crc11] = new CrcCustom<short>(11, 0x385, 0x1a, false, false, 0x00);
            _instances[(int)CrcPreset.Crc12Dect] = new CrcCustom<short>(12, 0x80f, 0x00, false, false, 0x00);
            _instances[(int)CrcPreset.Crc13Bbc] = new CrcCustom<short>(13, 0x1cf5, 0x000, false, false, 0x000);
            _instances[(int)CrcPreset.Crc14Darc] = new CrcCustom<short>(14, 0x2804, 0x000, true, true, 0x000);
            _instances[(int)CrcPreset.Crc15] = new CrcCustom<short>(15, 0x4599, 0x000, false, false, 0x000);
            _instances[(int)CrcPreset.Crc15Mpt1327] = new CrcCustom<short>(15, 0x6815, 0x000, false, false, 0x001);
            _instances[(int)CrcPreset.Crc16Usb] = new CrcCustom<ushort>(16, 0xa001, 0xffff, true, true, 0xffff);
            _instances[(int)CrcPreset.Crc24] = new CrcCustom<int>(24, 0x864cfb, 0xb704ce, false, false, 0x000000);
            _instances[(int)CrcPreset.Crc24FlexrayA] = new CrcCustom<int>(24, 0x5d6dcb, 0xfedcba, false, false, 0x000000);
            _instances[(int)CrcPreset.Crc24FlexrayB] = new CrcCustom<int>(24, 0x5d6dcb, 0xabcdef, false, false, 0x000000);
            _instances[(int)CrcPreset.Crc31Philips] = new CrcCustom<uint>(31, 0x4c11db7u, 0x7fffffffu, false, false, 0x7fffffffu);
            _instances[(int)CrcPreset.Crc32Jam] = new CrcCustom<uint>(32, 0xedb88320u, 0xffffffffu, true, true, 0x00000000u);
            _instances[(int)CrcPreset.Crc32Posix] = new CrcCustom<uint>(32, 0x04c11db7u, 0x00000000u, false, false, 0xffffffffu);
            _instances[(int)CrcPreset.Crc40Gsm] = new CrcCustom<long>(40, 0x0004820009L, 0x0000000000L, false, false, 0xffffffffffL);
            _instances[(int)CrcPreset.Crc64We] = new CrcCustom<ulong>(64, 0x42f0e1eba9ea3693uL, 0xffffffffffffffffuL, false, false, 0xffffffffffffffffuL);
            _instances[(int)CrcPreset.Crc64Xz] = new CrcCustom<ulong>(64, 0xc96c5795d7870f42uL, 0xffffffffffffffffuL, true, true, 0xffffffffffffffffuL);
        }

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Method")]
        public void InstanceEncrypt(CrcPreset algorithm, TestVarsType varsType, string expectedHash)
        {
            var instance = (dynamic)_instances[(int)algorithm];
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
