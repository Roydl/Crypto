namespace Roydl.Crypto.Internal
{
    using System;
    using System.IO;

    internal static class StreamHelper
    {
        internal static int GetBufferSize(this Stream stream)
        {
            const int m256 = 0x10000000;
            const int k128 = 0x20000;
            const int k64 = 0x10000;
            const int k32 = 0x8000;
            const int k16 = 0x4000;
            const int k8 = 0x2000;
            const int k4 = 0x1000;
            return stream switch
            {
                null => 0,
                BufferedStream => k4,
                MemoryStream ms => (int)Math.Min(ms.Length, m256),
                _ => (int)Math.Floor(stream.Length / 1.5d) switch
                {
                    > k128 => k128,
                    > k64 => k64,
                    > k32 => k32,
                    > k16 => k16,
                    > k8 => k8,
                    _ => k4
                }
            };
        }

        internal static int Read(this Stream stream, Span<byte> buffer, int length) =>
            stream!.Read(buffer.Length == length ? buffer : buffer[..length]);

        internal static void Write(this Stream stream, ReadOnlySpan<byte> buffer, int length) =>
            stream!.Write(buffer.Length == length ? buffer : buffer[..length]);
    }
}
