namespace Roydl.Crypto.Internal
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.Linq;
    using System.Numerics;

    internal static class NumericHelper
    {
        internal static TInt CreateBitMask<TInt>(int bitWidth) where TInt : struct, IComparable, IFormattable
        {
            var size = (int)MathF.Ceiling(bitWidth / 8f);
            switch (0xff.FromTo<int, TInt>())
            {
                case byte x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= (byte)(0xff << (8 * i));
                    return (TInt)(object)mask;
                }
                case short x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= (short)(0xff << (8 * i));
                    return (TInt)(object)mask;
                }
                case ushort x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= (ushort)(0xff << (8 * i));
                    return (TInt)(object)mask;
                }
                case int x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xff << (8 * i);
                    return (TInt)(object)mask;
                }
                case uint x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xffu << (8 * i);
                    return (TInt)(object)mask;
                }
                case long x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xffL << (8 * i);
                    return (TInt)(object)mask;
                }
                case ulong x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xffuL << (8 * i);
                    return (TInt)(object)mask;
                }
                case BigInteger x:
                {
                    var mask = x;
                    BigInteger b = 0xff;
                    for (var i = 1; i < size; i++)
                        mask ^= b << (8 * i);
                    return (TInt)(object)mask;
                }
                default:
                    throw new NotSupportedException();
            }
        }

        internal static TInt ReverseBits<TInt>(this TInt value) where TInt : struct, IComparable, IFormattable
        {
            // string conversion is slower than shifting bits,
            // but it more accurate for some unusual bit widths
            var bits = value switch
            {
                sbyte x => Convert.ToString(x, 2),
                byte x => Convert.ToString(x, 2),
                short x => Convert.ToString(x, 2),
                ushort x => Convert.ToString(x, 2),
                int x => Convert.ToString(x, 2),
                uint x => Convert.ToString(x, 2),
                long x => Convert.ToString(x, 2),
                ulong x => Convert.ToString((long)x, 2),
                _ => throw new NotSupportedException()
            };
            var size = bits.Length;
            while (size % 4 != 0)
                size++;
            if (bits.Length < size)
                bits = bits.PadLeft(size, '0');
            bits = new string(bits.Reverse().ToArray());
            return value switch
            {
                sbyte => (TInt)(object)Convert.ToSByte(bits, 2),
                byte => (TInt)(object)Convert.ToByte(bits, 2),
                short => (TInt)(object)Convert.ToInt16(bits, 2),
                ushort => (TInt)(object)Convert.ToUInt16(bits, 2),
                int => (TInt)(object)Convert.ToInt32(bits, 2),
                uint => (TInt)(object)Convert.ToUInt32(bits, 2),
                long => (TInt)(object)Convert.ToInt64(bits, 2),
                _ => (TInt)(object)Convert.ToUInt64(bits, 2)
            };
        }

        internal static TIntTo FromTo<TIntFrom, TIntTo>(this TIntFrom value) where TIntFrom : struct, IComparable, IFormattable where TIntTo : struct, IComparable, IFormattable
        {
            if (typeof(TIntFrom) == typeof(TIntTo))
                return (TIntTo)(object)value;

            /* slower and inaccurate when downsizing

                var current = value;
                return Unsafe.As<TIntFrom, TIntTo>(ref current);
            */

            // pretty fast unchecked assignment
            return default(TIntTo) switch
            {
                sbyte => value switch
                {
                    byte x => (TIntTo)(object)(sbyte)x,
                    short x => (TIntTo)(object)(sbyte)x,
                    ushort x => (TIntTo)(object)(sbyte)x,
                    int x => (TIntTo)(object)(sbyte)x,
                    uint x => (TIntTo)(object)(sbyte)x,
                    long x => (TIntTo)(object)(sbyte)x,
                    ulong x => (TIntTo)(object)(sbyte)x,
                    BigInteger x => (TIntTo)(object)(sbyte)(x & sbyte.MaxValue),
                    _ => throw new NotSupportedException()
                },
                byte => value switch
                {
                    sbyte x => (TIntTo)(object)(byte)x,
                    short x => (TIntTo)(object)(byte)x,
                    ushort x => (TIntTo)(object)(byte)x,
                    int x => (TIntTo)(object)(byte)x,
                    uint x => (TIntTo)(object)(byte)x,
                    long x => (TIntTo)(object)(byte)x,
                    ulong x => (TIntTo)(object)(byte)x,
                    BigInteger x => (TIntTo)(object)(byte)(x & byte.MaxValue),
                    _ => throw new NotSupportedException()
                },
                short => value switch
                {
                    sbyte x => (TIntTo)(object)(short)x,
                    byte x => (TIntTo)(object)(short)x,
                    ushort x => (TIntTo)(object)(short)x,
                    int x => (TIntTo)(object)(short)x,
                    uint x => (TIntTo)(object)(short)x,
                    long x => (TIntTo)(object)(short)x,
                    ulong x => (TIntTo)(object)(short)x,
                    BigInteger x => (TIntTo)(object)(short)(x & short.MaxValue),
                    _ => throw new NotSupportedException()
                },
                ushort => value switch
                {
                    sbyte x => (TIntTo)(object)(ushort)x,
                    byte x => (TIntTo)(object)(ushort)x,
                    short x => (TIntTo)(object)(ushort)x,
                    int x => (TIntTo)(object)(ushort)x,
                    uint x => (TIntTo)(object)(ushort)x,
                    long x => (TIntTo)(object)(ushort)x,
                    ulong x => (TIntTo)(object)(ushort)x,
                    BigInteger x => (TIntTo)(object)(ushort)(x & ushort.MaxValue),
                    _ => throw new NotSupportedException()
                },
                int => value switch
                {
                    sbyte x => (TIntTo)(object)(int)x,
                    byte x => (TIntTo)(object)(int)x,
                    short x => (TIntTo)(object)(int)x,
                    ushort x => (TIntTo)(object)(int)x,
                    uint x => (TIntTo)(object)(int)x,
                    long x => (TIntTo)(object)(int)x,
                    ulong x => (TIntTo)(object)(int)x,
                    BigInteger x => (TIntTo)(object)(int)(x & int.MaxValue),
                    _ => throw new NotSupportedException()
                },
                uint => value switch
                {
                    sbyte x => (TIntTo)(object)(uint)x,
                    byte x => (TIntTo)(object)(uint)x,
                    short x => (TIntTo)(object)(uint)x,
                    ushort x => (TIntTo)(object)(uint)x,
                    int x => (TIntTo)(object)(uint)x,
                    long x => (TIntTo)(object)(uint)x,
                    ulong x => (TIntTo)(object)(uint)x,
                    BigInteger x => (TIntTo)(object)(uint)(x & uint.MaxValue),
                    _ => throw new NotSupportedException()
                },
                long => value switch
                {
                    sbyte x => (TIntTo)(object)(long)x,
                    byte x => (TIntTo)(object)(long)x,
                    short x => (TIntTo)(object)(long)x,
                    ushort x => (TIntTo)(object)(long)x,
                    int x => (TIntTo)(object)(long)x,
                    uint x => (TIntTo)(object)(long)x,
                    ulong x => (TIntTo)(object)(long)x,
                    BigInteger x => (TIntTo)(object)(long)(x & long.MaxValue),
                    _ => throw new NotSupportedException()
                },
                ulong => value switch
                {
                    sbyte x => (TIntTo)(object)(ulong)x,
                    byte x => (TIntTo)(object)(ulong)x,
                    short x => (TIntTo)(object)(ulong)x,
                    ushort x => (TIntTo)(object)(ulong)x,
                    int x => (TIntTo)(object)(ulong)x,
                    uint x => (TIntTo)(object)(ulong)x,
                    long x => (TIntTo)(object)(ulong)x,
                    BigInteger x => (TIntTo)(object)(ulong)(x & ulong.MaxValue),
                    _ => throw new NotSupportedException()
                },
                BigInteger => value switch
                {
                    sbyte x => (TIntTo)(object)(BigInteger)x,
                    byte x => (TIntTo)(object)(BigInteger)x,
                    short x => (TIntTo)(object)(BigInteger)x,
                    ushort x => (TIntTo)(object)(BigInteger)x,
                    int x => (TIntTo)(object)(BigInteger)x,
                    uint x => (TIntTo)(object)(BigInteger)x,
                    long x => (TIntTo)(object)(BigInteger)x,
                    ulong x => (TIntTo)(object)(BigInteger)x,
                    _ => throw new NotSupportedException()
                },
                _ => throw new NotSupportedException()
            };
        }

        internal static string ToHexStr<TInt>(this TInt num, int padding, bool prefix) where TInt : struct, IComparable, IFormattable
        {
            var str = num.ToString("x2", null);
            if (padding > 2)
                str = str.PadLeft(padding, '0');
            if (prefix)
                str = $"0x{str}";
            return str;
        }

        internal static BigInteger ToBigInt([AllowNull] this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return BigInteger.Zero;
            var flags = value.StartsWith("0x") ? NumberStyles.HexNumber : NumberStyles.Any;
            if (flags == NumberStyles.HexNumber)
                value = value[2..];
            return BigInteger.TryParse(value, flags, null, out var result) ? result : BigInteger.Zero;
        }
    }
}
