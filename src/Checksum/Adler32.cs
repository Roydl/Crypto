namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using System.Runtime.Intrinsics;
    using System.Runtime.Intrinsics.X86;
    using Internal;
    using Resources;

    /// <summary>Provides functionality to compute Adler-32 hashes.</summary>
    public sealed class Adler32 : ChecksumAlgorithm<Adler32, uint>
    {
        private const int BlockSize = 16;
        private const uint ModAdler = 0xfff1u;

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        public Adler32() : base(32) => AlgorithmName = nameof(Adler32);

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        /// <returns>A newly created <see cref="Adler32"/> instance.</returns>
        public static Adler32 Create() => new();

        /// <inheritdoc/>
        public override unsafe void ComputeHash(Stream stream)
        {
            Reset();
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead)
                throw new NotSupportedException(ExceptionMessages.NotSupportedStreamRead);
            var sum1 = 1u;
            var sum2 = 0u;
            Span<byte> bytes = stackalloc byte[stream.GetBufferSize()];
            fixed (byte* input = bytes)
            {
                int len;
                while ((len = stream.Read(bytes)) > 0)
                    AppendData(input, len, ref sum1, ref sum2);
            }
            FinalizeHash(sum1, sum2);
        }

        /// <inheritdoc/>
        public override unsafe void ComputeHash(ReadOnlySpan<byte> bytes)
        {
            Reset();
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            var sum1 = 1u;
            var sum2 = 0u;
            fixed (byte* input = bytes)
                AppendData(input, bytes.Length, ref sum1, ref sum2);
            FinalizeHash(sum1, sum2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void AppendData(byte* input, int len, ref uint hash1, ref uint hash2)
        {
            var sum1 = hash1;
            var sum2 = hash2;
            var i = 0;
            if (Sse2.IsSupported)
            {
                while (len >= BlockSize)
                {
                    var v1 = Vector128.Create(sum1);
                    var v2 = Vector128.Create(sum2);
                    for (var j = 0; j < BlockSize; j++)
                    {
                        v1 = Sse2.Add(v1, Vector128.Create((uint)(input + i + j)[0]));
                        v2 = Sse2.Add(v1, v2);
                    }
                    sum1 = Sse2.ConvertToUInt32(v1);
                    sum2 = Sse2.ConvertToUInt32(v2);
                    if (sum2 >= ModAdler)
                        sum2 -= ModAdler;
                    i += BlockSize;
                    len -= BlockSize;
                    if (len % 0x8000 == 0)
                        sum1 %= ModAdler;
                }
            }
            else
            {
                while (len >= BlockSize)
                {
                    for (var j = 0; j < BlockSize; j++)
                    {
                        sum1 += (input + i + j)[0];
                        sum2 += sum1;
                    }
                    if (sum2 >= ModAdler)
                        sum2 -= ModAdler;
                    i += BlockSize;
                    len -= BlockSize;
                    if (len % 0x8000 == 0)
                        sum1 %= ModAdler;
                }
            }
            while (--len >= 0)
                AppendData(input[i++], ref sum1, ref sum2);
            hash1 = sum1;
            hash2 = sum2;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AppendData(byte value, ref uint hash1, ref uint hash2)
        {
            hash1 = (hash1 + value) % ModAdler;
            hash2 = (hash2 + hash1) % ModAdler;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void FinalizeHash(uint hash1, uint hash2)
        {
            var sum = ((hash2 << 16) | hash1) & uint.MaxValue;
            HashNumber = sum;
            RawHash = CryptoUtils.GetByteArray(sum, !BitConverter.IsLittleEndian);
        }
    }
}
