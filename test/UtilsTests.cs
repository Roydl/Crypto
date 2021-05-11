namespace Roydl.Crypto.Test
{
    using NUnit.Framework;

    [TestFixture]
    [NonParallelizable]
    [Platform(Include = TestVars.PlatformInclude)]
    public class UtilsTests
    {
        [Test]
        [TestCase(575792, null, null)]
        public void CombineHashCodes(int expected, object obj1, object obj2) => Assert.AreEqual(expected, CryptoUtils.CombineHashCodes(obj1, obj2));

        [Test]
        [TestCase(271354309, 10294120, 68356525)]
        public void CombineHashCodes(int expected, int hashCode1, int hashCode2) => Assert.AreEqual(expected, CryptoUtils.CombineHashCodes(hashCode1, hashCode2));
    }
}
