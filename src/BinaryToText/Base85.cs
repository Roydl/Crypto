namespace Roydl.Crypto.BinaryToText
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Text;
    using AbstractSamples;
    using Properties;

    /// <summary>
    ///     Provides functionality for translating data into the Base85 (also called
    ///     Ascii85) text representation and back.
    /// </summary>
    public sealed class Base85 : BinaryToTextSample
    {
        private static readonly byte[] EncodeBlock = new byte[5],
                                       DecodeBlock = new byte[4];

        private static readonly uint[] Pow85 =
        {
            85 * 85 * 85 * 85,
            85 * 85 * 85,
            85 * 85,
            85,
            1
        };

        /// <summary>
        ///     Initializes a new instance of the <see cref="Base85"/> class.
        /// </summary>
        [SuppressMessage("ReSharper", "EmptyConstructor")]
        public Base85() { }

        /// <summary>
        ///     Encodes the specified input stream into the specified output stream.
        /// </summary>
        /// <param name="inputStream">
        ///     The input stream to encode.
        /// </param>
        /// <param name="outputStream">
        ///     The output stream for encoding.
        /// </param>
        /// <param name="lineLength">
        ///     The length of lines.
        /// </param>
        /// <param name="dispose">
        ///     <see langword="true"/> to release all resources used by the input and
        ///     output <see cref="Stream"/>; otherwise, <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     inputStream or outputStream is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     inputStream or outputStream is invalid.
        /// </exception>
        /// <exception cref="NotSupportedException">
        ///     inputStream is not readable -or- outputStream is not writable.
        /// </exception>
        /// <exception cref="IOException">
        ///     An I/O error occurred, such as the specified file cannot be found.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///     Methods were called after the inputStream or outputStream was closed.
        /// </exception>
        public override void EncodeStream(Stream inputStream, Stream outputStream, int lineLength = 0, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            try
            {
                int b;
                var n = 0;
                var t = 0u;
                var p = 0;
                while ((b = inputStream.ReadByte()) != -1)
                {
                    if (n + 1 < DecodeBlock.Length)
                    {
                        t |= (uint)(b << (24 - n * 8));
                        n++;
                        continue;
                    }
                    t |= (uint)b;
                    if (t == 0)
                        WriteLine(outputStream, 0x7a, lineLength, ref p);
                    else
                    {
                        for (var i = EncodeBlock.Length - 1; i >= 0; i--)
                        {
                            EncodeBlock[i] = (byte)(t % 85 + 33);
                            t /= 85;
                        }
                        foreach (var eb in EncodeBlock)
                            WriteLine(outputStream, eb, lineLength, ref p);
                    }
                    t = 0;
                    n = 0;
                }
                if (n <= 0)
                    return;
                for (var i = EncodeBlock.Length - 1; i >= 0; i--)
                {
                    EncodeBlock[i] = (byte)(t % 85 + 33);
                    t /= 85;
                }
                for (var i = 0; i <= n; i++)
                    WriteLine(outputStream, EncodeBlock[i], lineLength, ref p);
            }
            finally
            {
                if (dispose)
                {
                    inputStream.Dispose();
                    outputStream.Dispose();
                }
            }
        }

        /// <summary>
        ///     Decodes the specified input stream into the specified output stream.
        /// </summary>
        /// <param name="inputStream">
        ///     The input stream to decode.
        /// </param>
        /// <param name="outputStream">
        ///     The output stream for decoding.
        /// </param>
        /// <param name="dispose">
        ///     <see langword="true"/> to release all resources used by the input and
        ///     output <see cref="Stream"/>; otherwise, <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     inputStream or outputStream is null.
        /// </exception>
        /// <exception cref="DecoderFallbackException">
        ///     inputStream contains invalid characters.
        /// </exception>
        /// <exception cref="NotSupportedException">
        ///     inputStream is not readable -or- outputStream is not writable.
        /// </exception>
        /// <exception cref="IOException">
        ///     An I/O error occurred, such as the specified file cannot be found.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        ///     Methods were called after the inputStream or outputStream was closed.
        /// </exception>
        public override void DecodeStream(Stream inputStream, Stream outputStream, bool dispose = false)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));
            try
            {
                int b;
                var n = 0;
                var t = 0u;
                while ((b = inputStream.ReadByte()) != -1)
                {
                    switch (b)
                    {
                        case 0x7a when n != 0:
                            throw new DecoderFallbackException(ExceptionMessages.FollowingCharCodeIsInvalid + 0x7a);
                        case 0x7a:
                        {
                            for (var i = 0; i < 4; i++)
                                DecodeBlock[i] = 0;
                            outputStream.Write(DecodeBlock, 0, DecodeBlock.Length);
                            continue;
                        }
                        case '\0' or '\t' or '\n' or '\r' or ' ':
                            continue;
                        case < 0x21 or > 0x75:
                            throw new DecoderFallbackException(ExceptionMessages.FollowingCharCodeIsInvalid + b);
                    }
                    t += (uint)((b - 33) * Pow85[n]);
                    n++;
                    if (n != EncodeBlock.Length)
                        continue;
                    for (var i = 0; i < DecodeBlock.Length; i++)
                        DecodeBlock[i] = (byte)(t >> (24 - i * 8));
                    outputStream.Write(DecodeBlock, 0, DecodeBlock.Length);
                    t = 0;
                    n = 0;
                }
                switch (n)
                {
                    case 0:
                        return;
                    case 1:
                        throw new DecoderFallbackException(ExceptionMessages.LastBlockIsSingleByte);
                }
                n--;
                t += Pow85[n];
                for (var i = 0; i < n; i++)
                    DecodeBlock[i] = (byte)(t >> (24 - i * 8));
                for (var i = 0; i < n; i++)
                    outputStream.WriteByte(DecodeBlock[i]);
            }
            finally
            {
                if (dispose)
                {
                    inputStream.Dispose();
                    outputStream.Dispose();
                }
            }
        }
    }
}
