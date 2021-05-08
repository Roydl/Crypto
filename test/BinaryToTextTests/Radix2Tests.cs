namespace Roydl.Crypto.Test.BinaryToTextTests
{
    using System;
    using System.IO;
    using AbstractSamples;
    using BinaryToText;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = Vars.PlatformInclude)]
    public class Radix2Tests
    {
        private const BinaryToTextEncoding Algorithm = BinaryToTextEncoding.Radix2;
        private const string ExpectedTestEncoded = "01010100011001010111001101110100";
        private const string ExpectedRangeEncoded = "00000000000000010000001000000011000001000000010100000110000001110000100000001001000010100000101100001100000011010000111000001111000100000001000100010010000100110001010000010101000101100001011100011000000110010001101000011011000111000001110100011110000111110010000000100001001000100010001100100100001001010010011000100111001010000010100100101010001010110010110000101101001011100010111100110000001100010011001000110011001101000011010100110110001101110011100000111001001110100011101100111100001111010011111000111111010000000100000101000010010000110100010001000101010001100100011101001000010010010100101001001011010011000100110101001110010011110101000001010001010100100101001101010100010101010101011001010111010110000101100101011010010110110101110001011101010111100101111101100000011000010110001001100011011001000110010101100110011001110110100001101001011010100110101101101100011011010110111001101111011100000111000101110010011100110111010001110101011101100111011101111000011110010111101001111011011111000111110101111110011111111100001010000000110000101000000111000010100000101100001010000011110000101000010011000010100001011100001010000110110000101000011111000010100010001100001010001001110000101000101011000010100010111100001010001100110000101000110111000010100011101100001010001111110000101001000011000010100100011100001010010010110000101001001111000010100101001100001010010101110000101001011011000010100101111100001010011000110000101001100111000010100110101100001010011011110000101001110011000010100111011100001010011110110000101001111111000010101000001100001010100001110000101010001011000010101000111100001010100100110000101010010111000010101001101100001010100111110000101010100011000010101010011100001010101010110000101010101111000010101011001100001010101101110000101010111011000010101011111100001010110000110000101011000111000010101100101100001010110011110000101011010011000010101101011100001010110110110000101011011111000010101110001100001010111001110000101011101011000010101110111100001010111100110000101011110111000010101111101100001010111111110000111000000011000011100000011100001110000010110000111000001111000011100001001100001110000101110000111000011011000011100001111100001110001000110000111000100111000011100010101100001110001011110000111000110011000011100011011100001110001110110000111000111111000011100100001100001110010001110000111001001011000011100100111100001110010100110000111001010111000011100101101100001110010111110000111001100011000011100110011100001110011010110000111001101111000011100111001100001110011101110000111001111011000011100111111100001110100000110000111010000111000011101000101100001110100011110000111010010011000011101001011100001110100110110000111010011111000011101010001100001110101001110000111010101011000011101010111100001110101100110000111010110111000011101011101100001110101111110000111011000011000011101100011100001110110010110000111011001111000011101101001100001110110101110000111011011011000011101101111100001110111000110000111011100111000011101110101100001110111011110000111011110011000011101111011100001110111110";
        private const string TestFileSrcPath = ".\\testBinToText.Src.Radix2";
        private const string TestFileDestPath = ".\\testBinToText.Dest.Radix2";
        public static readonly string RangeStr = Vars.CharRangeStr;

        private static readonly TestCaseData[] TestData =
        {
            new(TestDataVarsType.TestStream, ExpectedTestEncoded),
            new(TestDataVarsType.TestBytes, ExpectedTestEncoded),
            new(TestDataVarsType.TestString, ExpectedTestEncoded),
            new(TestDataVarsType.TestFile, ExpectedTestEncoded),
            new(TestDataVarsType.RangeString, ExpectedRangeEncoded)
        };

        private static Radix2 _instance;

        [OneTimeSetUp]
        public void CreateInstance()
        {
            _instance = new Radix2();
            File.WriteAllText(TestFileSrcPath, Vars.TestStr);
        }

        [OneTimeSetUp]
        public void ProcessExit()
        {
            AppDomain.CurrentDomain.ProcessExit += RemoveTestFile;

            static void RemoveTestFile(object sender, EventArgs args)
            {
                if (File.Exists(TestFileSrcPath))
                    File.Delete(TestFileSrcPath);
                if (File.Exists(TestFileDestPath))
                    File.Delete(TestFileDestPath);
            }
        }

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Extension")]
        public void ExtensionEncodeDecode(TestDataVarsType varsType, string expectedEncoded)
        {
            object original, decoded;
            string encoded;
            switch (varsType)
            {
                case TestDataVarsType.TestStream:
                    // No extension for streams
                    return;
                case TestDataVarsType.TestBytes:
                    original = Vars.TestBytes;
                    encoded = ((byte[])original).Encode(Algorithm);
                    decoded = encoded.Decode(Algorithm);
                    break;
                case TestDataVarsType.TestString:
                    original = Vars.TestStr;
                    encoded = ((string)original).Encode(Algorithm);
                    decoded = encoded.DecodeString(Algorithm);
                    break;
                case TestDataVarsType.TestFile:
                    Assert.IsTrue(_instance.EncodeFile(TestFileSrcPath, TestFileDestPath));
                    original = Vars.TestBytes;
                    encoded = TestFileSrcPath.EncodeFile(Algorithm);
                    decoded = TestFileDestPath.DecodeFile(Algorithm);
                    break;
                case TestDataVarsType.QuoteString:
                    original = Vars.QuoteStr;
                    encoded = ((string)original).Encode(Algorithm);
                    decoded = encoded.DecodeString(Algorithm);
                    break;
                case TestDataVarsType.RangeString:
                    original = Vars.ByteRangeStr;
                    encoded = ((string)original).Encode(Algorithm);
                    decoded = encoded.DecodeString(Algorithm);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedEncoded, encoded);
            Assert.AreEqual(original, decoded);
        }

        [Test]
        [Category("New")]
        public void InstanceCtor()
        {
            var instanceDefault = new Radix2();
            Assert.IsInstanceOf(typeof(Radix2), instanceDefault);
            Assert.IsInstanceOf(typeof(BinaryToTextSample), instanceDefault);
            Assert.AreNotSame(_instance, instanceDefault);
        }

        [Test]
        [TestCaseSource(nameof(TestData))]
        [Category("Method")]
        public void InstanceEncodeDecode(TestDataVarsType varsType, string expectedEncoded)
        {
            object original, decoded;
            string encoded;
            switch (varsType)
            {
                case TestDataVarsType.TestStream:
                    original = Vars.TestBytes;

                    // dispose
                    using (var msi = new MemoryStream((byte[])original))
                    {
                        var mso = new MemoryStream();
                        _instance.EncodeStream(msi, mso, true);
                        try
                        {
                            msi.Position = 0L;
                        }
                        catch (Exception e)
                        {
                            Assert.AreEqual(typeof(ObjectDisposedException), e.GetType());
                        }
                        try
                        {
                            mso.Position = 0L;
                        }
                        catch (Exception e)
                        {
                            Assert.AreEqual(typeof(ObjectDisposedException), e.GetType());
                        }
                    }

                    // encode
                    using (var msi = new MemoryStream((byte[])original))
                    {
                        using var mso = new MemoryStream();
                        _instance.EncodeStream(msi, mso);
                        encoded = Vars.Utf8NoBom.GetString(mso.ToArray());
                    }

                    // decode
                    using (var msi = new MemoryStream(Vars.Utf8NoBom.GetBytes(encoded)))
                    {
                        using var mso = new MemoryStream();
                        _instance.DecodeStream(msi, mso);
                        decoded = mso.ToArray();
                    }
                    break;
                case TestDataVarsType.TestBytes:
                    original = Vars.TestBytes;
                    encoded = _instance.EncodeBytes((byte[])original);
                    decoded = _instance.DecodeBytes(encoded);
                    break;
                case TestDataVarsType.TestString:
                    original = Vars.TestStr;
                    encoded = _instance.EncodeString((string)original);
                    decoded = _instance.DecodeString(encoded);
                    break;
                case TestDataVarsType.TestFile:
                    Assert.IsTrue(_instance.EncodeFile(TestFileSrcPath, TestFileDestPath));
                    original = Vars.TestBytes;
                    encoded = _instance.EncodeFile(TestFileSrcPath);
                    decoded = _instance.DecodeFile(TestFileDestPath);
                    break;
                case TestDataVarsType.QuoteString:
                    original = Vars.QuoteStr;
                    encoded = _instance.EncodeString((string)original);
                    decoded = _instance.DecodeString(encoded);
                    break;
                case TestDataVarsType.RangeString:
                    original = Vars.ByteRangeStr;
                    encoded = _instance.EncodeString((string)original);
                    decoded = _instance.DecodeString(encoded);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(varsType), varsType, null);
            }
            Assert.AreEqual(expectedEncoded, encoded);
            Assert.AreEqual(original, decoded);
        }

        [Test]
        [Category("Method")]
        public void InstanceGetHashCode() =>
            Assert.AreNotEqual(0, _instance.GetHashCode());

        [Test]
        [Category("Method")]
        public void InstanceToString() =>
            Assert.AreEqual("Roydl.Crypto.BinaryToText.Radix2", _instance.ToString());
    }
}
