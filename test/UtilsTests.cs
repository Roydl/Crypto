namespace Roydl.Crypto.Test
{
    using NUnit.Framework;

    [TestFixture]
    public class UtilsTests
    {
        [Test]
        public void CombineHashCodesTest1() => Assert.AreEqual(575792, Utils.CombineHashCodes(null, null));

        [Test]
        public void CombineHashCodesTest2() => Assert.AreEqual(271354309, Utils.CombineHashCodes(10294120, 68356525));
    }
}
