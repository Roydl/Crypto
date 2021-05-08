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
    public class Radix8Tests
    {
        private const BinaryToTextEncoding Algorithm = BinaryToTextEncoding.Radix8;
        private const string ExpectedTestEncoded = "124145163164";
        private const string ExpectedRangeEncoded = "000001002003004005006007010011012013014015016017020021022023024025026027030031032033034035036037040041042043044045046047050051052053054055056057060061062063064065066067070071072073074075076077100101102103104105106107110111112113114115116117120121122123124125126127130131132133134135136137140141142143144145146147150151152153154155156157160161162163164165166167170171172173174175176177302200302201302202302203302204302205302206302207302210302211302212302213302214302215302216302217302220302221302222302223302224302225302226302227302230302231302232302233302234302235302236302237302240302241302242302243302244302245302246302247302250302251302252302253302254302255302256302257302260302261302262302263302264302265302266302267302270302271302272302273302274302275302276302277303200303201303202303203303204303205303206303207303210303211303212303213303214303215303216303217303220303221303222303223303224303225303226303227303230303231303232303233303234303235303236303237303240303241303242303243303244303245303246303247303250303251303252303253303254303255303256303257303260303261303262303263303264303265303266303267303270303271303272303273303274303275303276";
        private const string TestFileSrcPath = ".\\testBinToText.Src.Radix8";
        private const string TestFileDestPath = ".\\testBinToText.Dest.Radix8";
        public static readonly string RangeStr = Vars.CharRangeStr;

        private static readonly TestCaseData[] TestData =
        {
            new(TestDataVarsType.TestStream, ExpectedTestEncoded),
            new(TestDataVarsType.TestBytes, ExpectedTestEncoded),
            new(TestDataVarsType.TestString, ExpectedTestEncoded),
            new(TestDataVarsType.TestFile, ExpectedTestEncoded),
            new(TestDataVarsType.RangeString, ExpectedRangeEncoded)
        };

        private static Radix8 _instance;

        [OneTimeSetUp]
        public void CreateInstance()
        {
            _instance = new Radix8();
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
            var instanceDefault = new Radix8();
            Assert.IsInstanceOf(typeof(Radix8), instanceDefault);
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
            Assert.AreEqual("Roydl.Crypto.BinaryToText.Radix8", _instance.ToString());
    }
}
