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
    public class Base85Tests
    {
        private const BinaryToTextEncoding Algorithm = BinaryToTextEncoding.Base85;
        private const string ExpectedTestEncoded = "<+U,m";
        private const string ExpectedRangeEncoded = "!!*-'\"9eu7#RLhG$k3[W&.oNg'GVB\"(`=52*$$(B+<_pR,UFcb-n-Vr/1iJ-0JP==1c70M3&s#]4?Ykm5X@_(6q'R884cEH9MJ8X:f1+h<)lt#=BSg3>[:ZC?t!MSA7]@cBPD3sCi+'.E,fo>FEMbNG^4U^I!pHn_LTLS_LfXW_M#d[_M5p__MH'c_MZ3g_Ml?k_N)Ko_N;Ws_NMd\"_N_p&_Nr'*_O/3._OA?2_OSK6_OeW:_P\"c>_P4oB_PG&F_PY2J_Pk>N_Q(JR_Q:VV_QLbZ_Q^n^_Qq%b_R.1f_R@=j_RRIn_RdUr_S!b!_S3n%_goXU_h,dY_h>p]_hQ'a_hc3e_hu?i_i2Km_iDWq_iVcu_ihp$_j&'(_j83,_jJ?0_j\\K4_jnW8_k+c<_k=o@_kP&D_kb2H_kt>L_l1JP_lCVT_lUbX_lgn\\_m%%`_m71d_mI=h_m[Il_mmUp_n*at_n<n#_nH";
        private const string TestFileSrcPath = ".\\testBinToText.Src.Base85";
        private const string TestFileDestPath = ".\\testBinToText.Dest.Base85";
        public static readonly string RangeStr = Vars.CharRangeStr;

        private static readonly TestCaseData[] TestData =
        {
            new(TestDataVarsType.TestStream, ExpectedTestEncoded),
            new(TestDataVarsType.TestBytes, ExpectedTestEncoded),
            new(TestDataVarsType.TestString, ExpectedTestEncoded),
            new(TestDataVarsType.TestFile, ExpectedTestEncoded),
            new(TestDataVarsType.RangeString, ExpectedRangeEncoded)
        };

        private static Base85 _instance;

        [OneTimeSetUp]
        public void CreateInstance()
        {
            _instance = new Base85();
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
            var instanceDefault = new Base85();
            Assert.IsInstanceOf(typeof(Base85), instanceDefault);
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
            Assert.AreEqual("Roydl.Crypto.BinaryToText.Base85", _instance.ToString());
    }
}
