namespace Roydl.Crypto.Test.BinaryToTextTests
{
    using System;
    using System.IO;
    using System.Text;
    using AbstractSamples;
    using BinaryToText;
    using NUnit.Framework;

    [TestFixture]
    [Parallelizable]
    [Platform(Include = Vars.PlatformInclude)]
    public class Base64Tests
    {
        private const string ExpectedTestEncoded = "VGVzdA==";
        private const string ExpectedRangeEncoded = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn/CgMKBwoLCg8KEwoXChsKHwojCicKKwovCjMKNwo7Cj8KQwpHCksKTwpTClcKWwpfCmMKZwprCm8Kcwp3CnsKfwqDCocKiwqPCpMKlwqbCp8KowqnCqsKrwqzCrcKuwq/CsMKxwrLCs8K0wrXCtsK3wrjCucK6wrvCvMK9wr7Cv8OAw4HDgsODw4TDhcOGw4fDiMOJw4rDi8OMw43DjsOPw5DDkcOSw5PDlMOVw5bDl8OYw5nDmsObw5zDncOew5/DoMOhw6LDo8Okw6XDpsOnw6jDqcOqw6vDrMOtw67Dr8Oww7HDssOzw7TDtcO2w7fDuMO5w7rDu8O8w73Dvg==";
        private static readonly string TestFileSrcPath = Path.GetTempFileName();
        private static readonly string TestFileDestPath = Path.GetTempFileName();

        private static readonly TestCaseData[] TestData =
        {
            new(TestDataVarsType.TestStream, ExpectedTestEncoded),
            new(TestDataVarsType.TestBytes, ExpectedTestEncoded),
            new(TestDataVarsType.TestString, ExpectedTestEncoded),
            new(TestDataVarsType.TestFile, ExpectedTestEncoded),
            new(TestDataVarsType.RangeString, ExpectedRangeEncoded)
        };

        private static Base64 _instance;

        [OneTimeSetUp]
        public void CreateInstance()
        {
            _instance = new Base64();
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
                    encoded = ((byte[])original).Encode();
                    decoded = encoded.Decode();
                    break;
                case TestDataVarsType.TestString:
                    original = Vars.TestStr;
                    encoded = ((string)original).Encode();
                    decoded = encoded.DecodeString();
                    break;
                case TestDataVarsType.TestFile:
                    Assert.IsTrue(_instance.EncodeFile(TestFileSrcPath, TestFileDestPath));
                    original = Vars.TestBytes;
                    encoded = TestFileSrcPath.EncodeFile();
                    decoded = TestFileDestPath.DecodeFile();
                    break;
                case TestDataVarsType.QuoteString:
                    original = Vars.QuoteStr;
                    encoded = ((string)original).Encode();
                    decoded = encoded.DecodeString();
                    break;
                case TestDataVarsType.RangeString:
                    original = Vars.RangeStr;
                    encoded = ((string)original).Encode();
                    decoded = encoded.DecodeString();
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
            var instanceDefault = new Base64();
            Assert.IsInstanceOf(typeof(Base64), instanceDefault);
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
                        encoded = Encoding.UTF8.GetString(mso.ToArray());
                    }

                    // decode
                    using (var msi = new MemoryStream(Encoding.UTF8.GetBytes(encoded)))
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
                    original = Vars.RangeStr;
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
            Assert.AreEqual("Roydl.Crypto.BinaryToText.Base64", _instance.ToString());
    }
}
