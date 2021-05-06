namespace Roydl.Crypto.Test
{
    using System;
    using System.IO;
    using AbstractSamples;
    using Checksum;
    using NUnit.Framework;

    [TestFixture]
    public class ChecksumTests
    {
        private static void TestHelper<T>(T instance, ChecksumAlgorithm algorithm, string originalText, string expectedHash) where T : ChecksumSample
        {
            var str = originalText.Encrypt(algorithm);
            Assert.AreEqual(expectedHash, str);

            var path = $".\\testFileChecksum.{algorithm}";
            var buffer = new byte[ushort.MaxValue];
            new Random().NextBytes(buffer);
            File.WriteAllBytes(path, buffer);
            instance.EncryptFile(path);
            Assert.AreEqual(instance.HashLength, instance.Hash.Length);

            str = path.EncryptFile(algorithm);
            Assert.AreEqual(instance.HashLength, str?.Length);
            File.Delete(path);
        }

        [Test]
        [TestCase(TestOf = typeof(Adler32))]
        public void Adler32Test1() => TestHelper(new Adler32(), ChecksumAlgorithm.Adler32, Vars.TestText1, "ac4410f7");

        [Test]
        [TestCase(TestOf = typeof(Adler32))]
        public void Adler32Test2() => TestHelper(new Adler32(), ChecksumAlgorithm.Adler32, Vars.TestText2, "f923cf3f");

        [Test]
        [TestCase(TestOf = typeof(Crc16))]
        public void Crc16Test1() => TestHelper(new Crc16(), ChecksumAlgorithm.Crc16, Vars.TestText1, "d4b3");

        [Test]
        [TestCase(TestOf = typeof(Crc16))]
        public void Crc16Test2() => TestHelper(new Crc16(), ChecksumAlgorithm.Crc16, Vars.TestText2, "113b");

        [Test]
        [TestCase(TestOf = typeof(Crc32))]
        public void Crc32Test1() => TestHelper(new Crc32(), ChecksumAlgorithm.Crc32, Vars.TestText1, "75edf6dd");

        [Test]
        [TestCase(TestOf = typeof(Crc32))]
        public void Crc32Test2() => TestHelper(new Crc32(), ChecksumAlgorithm.Crc32, Vars.TestText2, "7ad6d652");

        [Test]
        [TestCase(TestOf = typeof(Crc64))]
        public void Crc64Test1() => TestHelper(new Crc64(), ChecksumAlgorithm.Crc64, Vars.TestText1, "a99bd111a253ded5");

        [Test]
        [TestCase(TestOf = typeof(Crc64))]
        public void Crc64Test2() => TestHelper(new Crc64(), ChecksumAlgorithm.Crc64, Vars.TestText2, "59d3e35dccce4de9");

        [Test]
        [TestCase(TestOf = typeof(Md5))]
        public void Md5Test1() => TestHelper(new Md5(), ChecksumAlgorithm.Md5, Vars.TestText1, "c852cafd9bcd44af03e56f1412be1539");

        [Test]
        [TestCase(TestOf = typeof(Md5))]
        public void Md5Test2() => TestHelper(new Md5(), ChecksumAlgorithm.Md5, Vars.TestText2, "5a0c0409012b80574187d68e43857c5f");

        [Test]
        [TestCase(TestOf = typeof(Sha1))]
        public void Sha1Test1() => TestHelper(new Sha1(), ChecksumAlgorithm.Sha1, Vars.TestText1, "8cd3f7b5fb255b5ddc6627db0421652104afa0d5");

        [Test]
        [TestCase(TestOf = typeof(Sha1))]
        public void Sha1Test2() => TestHelper(new Sha1(), ChecksumAlgorithm.Sha1, Vars.TestText2, "60dd4bf59289437e8f18bfbadb6613072d5c6f2c");

        [Test]
        [TestCase(TestOf = typeof(Sha256))]
        public void Sha256Test1() => TestHelper(new Sha256(), ChecksumAlgorithm.Sha256, Vars.TestText1, "8ffaedd2652dff3df2a133341f6d635f9424401c7c480ad694dc2ef5cd3269ac");

        [Test]
        [TestCase(TestOf = typeof(Sha256))]
        public void Sha256Test2() => TestHelper(new Sha256(), ChecksumAlgorithm.Sha256, Vars.TestText2, "7fb98786c16c175d232ab161b5e604c5792e6befd4e1e8d4ecac9d568a6db524");

        [Test]
        [TestCase(TestOf = typeof(Sha384))]
        public void Sha384Test1() => TestHelper(new Sha384(), ChecksumAlgorithm.Sha384, Vars.TestText1, "98a875ea0bf5067afe1c3ee86dd364f892891c8d656e3ea418ade6bda54caf10d2e8152646d9f044b1950dc37fe63121");

        [Test]
        [TestCase(TestOf = typeof(Sha384))]
        public void Sha384Test2() => TestHelper(new Sha384(), ChecksumAlgorithm.Sha384, Vars.TestText2, "dd39f42bdb371db2efbaa9d7ed505c332c42e7a900960a8a40fe4890e4de4bb83fa633417844bf1fec41ba9b46a1a522");

        [Test]
        [TestCase(TestOf = typeof(Sha512))]
        public void Sha512Test1() => TestHelper(new Sha512(), ChecksumAlgorithm.Sha512, Vars.TestText1, "951cb5d110ca6127b42a5ef2580c36317daf52e27b116f7e8967bf2db9aa71bfa3b9e963cc1ee06f92a313e576a7563eeade3250a7eae4527bbba24918ea2d99");

        [Test]
        [TestCase(TestOf = typeof(Sha512))]
        public void Sha512Test2() => TestHelper(new Sha512(), ChecksumAlgorithm.Sha512, Vars.TestText2, "0523f0b765970e2d2b04eb14e2f797b0c4d4b348b02dc5b7d16e49a0fdff3328ab711490b02b9fb6d7c71c7ac529e2c98c2719b7cf7561b1221b33397931af74");

        [Test]
        [TestCase(Description = "Computes a CRC-32 and a SHA-256 hash and combines both to form a GUID.")]
        public void SimpleGuidTest1() => Assert.AreEqual("75edf6dd-8ffa-edd2-652d-2ef5cd3269ac", Vars.TestText1.GetGuid());

        [Test]
        [TestCase(Description = "Computes a Adler32 and a CRC-16 hash and combines both to form a GUID.")]
        public void SimpleGuidTest2() => Assert.AreEqual("{ac4410f7-ac44-10f7-0000-ac4410f70000}", Vars.TestText1.GetGuid(true, ChecksumAlgorithm.Adler32, ChecksumAlgorithm.Crc16));
    }
}
