namespace Roydl.Crypto.Test
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;

    public enum TestSetting
    {
        Default,
        Hmac
    }

    public enum TestVarsType
    {
        InitOnly,
        TestStream,
        TestBytes,
        TestString,
        TestFile,
        QuoteString,
        RangeString
    }

    public static class TestVars
    {
        public const string PlatformInclude = "Win32NT,Linux";
        public const string QuoteStr = "We know what we are, but know not what we may be.";
        public const string TestStr = "Test";
        public static readonly byte[] TestBytes = { 0x54, 0x65, 0x73, 0x74 };

        public static readonly byte[] TestSecretKey =
        {
            0x16, 0xdf, 0x96, 0xc6, 0x7b, 0xa7, 0xda, 0x9f,
            0xc2, 0xa9, 0xfb, 0xc6, 0x3b, 0x37, 0xaa, 0xb9,
            0x94, 0x98, 0x3d, 0x3d, 0xc6, 0x81, 0xe0, 0x52,
            0x22, 0x3a, 0x1b, 0x3e, 0xf2, 0xc0, 0x5f, 0x3d,
            0xaf, 0x35, 0x7f, 0x4b, 0xbc, 0x7b, 0xcb, 0x91,
            0xf8, 0x66, 0xc9, 0x8d, 0xeb, 0x83, 0xba, 0x19,
            0x50, 0x5d, 0x24, 0x00, 0x7d, 0xd6, 0x10, 0x95,
            0xfe, 0x44, 0xa4, 0x41, 0x8c, 0x9b, 0xad, 0x01
        };

        public static Random Randomizer => new();

        public static Stopwatch StopWatch => new();

        public static string RangeStr { get; } = new(Enumerable.Range(byte.MinValue, byte.MaxValue).Select(i => (char)i).ToArray());

        public static int GetRandomInt() =>
            Randomizer.Next(1, short.MaxValue);

        public static byte[] GetRandomBytes(int size = 0)
        {
            if (size < 1)
            {
                size = Randomizer.Next(byte.MaxValue, short.MaxValue);
                if (size % 2 == 0)
                    --size;
            }
            var bytes = new byte[size];
            Randomizer.NextBytes(bytes);
            return bytes;
        }

        public static string GetTempFilePath(string name)
        {
            var dir = Environment.CurrentDirectory;
            if (!Directory.Exists(dir)) // broken dir on some test platforms 
                dir = AppDomain.CurrentDomain.BaseDirectory;
            return Path.Combine(dir, $"test-{name}-{Guid.NewGuid()}.tmp");
        }
    }
}
