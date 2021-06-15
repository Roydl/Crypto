namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using Internal;
    using Resources;

    /// <summary>Provides functionality to compute Adler-32 hashes.</summary>
    public sealed class Adler32 : ChecksumAlgorithm<Adler32, uint>
    {
        private const int BlockSize = 8;
        private const uint ModAdler = 0xfff1u;

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        public Adler32() : base(32) => AlgorithmName = nameof(Adler32);

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        /// <returns>A newly created <see cref="Adler32"/> instance.</returns>
        public static Adler32 Create() => new();

        /// <inheritdoc/>
        public override void ComputeHash(Stream stream)
        {
            Reset();
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead)
                throw new NotSupportedException(ExceptionMessages.NotSupportedStreamRead);
            Span<uint> sum = stackalloc[] { 1u, 0u };
            Span<byte> bytes = stackalloc byte[stream.GetBufferSize()];
            int len;
            while ((len = stream.Read(bytes)) > 0)
                AppendData(bytes, len, ref sum);
            FinalizeHash(sum);
        }

        /// <inheritdoc/>
        public override void ComputeHash(ReadOnlySpan<byte> bytes)
        {
            Reset();
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            Span<uint> sum = stackalloc[] { 1u, 0u };
            AppendData(bytes, bytes.Length, ref sum);
            FinalizeHash(sum);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AppendData(ReadOnlySpan<byte> bytes, int len, ref Span<uint> hash)
        {
            var sum = hash;
            var i = 0;
            while (len >= BlockSize)
            {
                for (var j = 0; j < BlockSize; j++)
                {
                    sum[0] += bytes[i + j];
                    sum[1] += sum[0];
                }
                if (sum[1] >= ModAdler)
                    sum[1] -= ModAdler;

                i += BlockSize;
                len -= BlockSize;
                if (len % 0x8000 == 0)
                    sum[0] %= ModAdler;
            }
            while (--len >= 0)
                AppendData(bytes[i++], ref sum);
            hash = sum;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AppendData(byte value, ref Span<uint> hash)
        {
            hash[0] = (hash[0] + value) % ModAdler;
            hash[1] = (hash[1] + hash[0]) % ModAdler;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void FinalizeHash(ReadOnlySpan<uint> hash)
        {
            var sum = ((hash[1] << 16) | hash[0]) & uint.MaxValue;
            HashNumber = sum;
            RawHash = CryptoUtils.GetByteArray(sum, !BitConverter.IsLittleEndian);
        }
    }
}
