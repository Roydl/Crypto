namespace Roydl.Crypto.Test
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

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
        private static readonly Random Randomizer = new();
        public const string PlatformInclude = "Win32NT,Linux";
        public const string QuoteStr = "We know what we are, but know not what we may be.";
        public const string TestStr = "Test";
        public static readonly byte[] TestBytes = { 0x54, 0x65, 0x73, 0x74 };

        public static string ByteRangeStr { get; } = new(Enumerable.Range(byte.MinValue, byte.MaxValue).Select(i => (char)i).ToArray());

        public static string CharRangeStr { get; } = new(Enumerable.Range(char.MinValue, char.MaxValue).Select(i => (char)i).ToArray());

        public static Encoding Utf8NoBom { get; } = new UTF8Encoding(false);

        public static int GetRandomInt() => 
            Randomizer.Next(1, 1048575);

        public static byte[] GetRandomBytes()
        {
            var bytes = new byte[Randomizer.Next(ushort.MaxValue, 1048575)];
            Randomizer.NextBytes(bytes);
            return bytes;
        }
    }
}
