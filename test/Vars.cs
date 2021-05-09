namespace Roydl.Crypto.Test
{
    using System;
    using System.Linq;

    public enum TestDataVarsType
    {
        TestStream,
        TestBytes,
        TestString,
        TestFile,
        QuoteString,
        RangeString
    }

    public static class Vars
    {
        public const string PlatformInclude = "Win32NT,Linux";
        public const string QuoteStr = "We know what we are, but know not what we may be.";
        public const string TestStr = "Test";
        public static readonly byte[] TestBytes = { 0x54, 0x65, 0x73, 0x74 };
        private static readonly Random Randomizer = new();

        public static string RangeStr { get; } = new(Enumerable.Range(byte.MinValue, byte.MaxValue).Select(i => (char)i).ToArray());

        public static int GetRandomInt() =>
            Randomizer.Next(1, short.MaxValue);

        public static byte[] GetRandomBytes()
        {
            var bytes = new byte[Randomizer.Next(short.MaxValue, ushort.MaxValue)];
            Randomizer.NextBytes(bytes);
            return bytes;
        }
    }
}
