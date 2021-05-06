namespace Roydl.Crypto.Test
{
    using System.Linq;

    public static class Vars
    {
        public const string TestText1 = "We know what we are, but know not what we may be.";
        public static readonly string TestText2 = new(Enumerable.Range(byte.MinValue, byte.MaxValue).Select(i => (char)i).ToArray());
    }
}
